/*
 *    Copyright (c) 2017, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   The file implements the Thread border agent.
 */

#include "agent/border_agent.hpp"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent/border_agent.hpp"
#include "agent/ncp.hpp"
#include "agent/uris.hpp"
#include "common/code_utils.hpp"
#include "common/logging.hpp"
#include "common/tlv.hpp"
#include "common/types.hpp"
#include "utils/hex.hpp"
#include "utils/strcpy_utils.hpp"

#define OTBR_LOG_TAG "Border Agent"

namespace otbr {

static const char    kBorderAgentServiceType[]    = "_meshcop._udp"; ///< Border agent service type of mDNS
static constexpr int kBorderAgentServiceDummyPort = 49152;

/**
 * Locators
 *
 */
enum
{
    kAloc16Leader   = 0xfc00, ///< leader anycast locator.
    kInvalidLocator = 0xffff, ///< invalid locator.
};

enum : uint8_t
{
    kConnectionModeDisabled = 0,
    kConnectionModePskc     = 1,
    kConnectionModePskd     = 2,
    kConnectionModeVendor   = 3,
    kConnectionModeX509     = 4,
};

enum : uint8_t
{
    kThreadIfStatusNotInitialized = 0,
    kThreadIfStatusInitialized    = 1,
    kThreadIfStatusActive         = 2,
};

enum : uint8_t
{
    kAvailabilityInfrequent = 0,
    kAvailabilityHigh       = 1,
};

struct StateBitmap
{
    uint32_t mConnectionMode : 3;
    uint32_t mThreadIfStatus : 2;
    uint32_t mAvailability : 2;
    uint32_t mBbrIsActive : 1;
    uint32_t mBbrIsPrimary : 1;

    StateBitmap(void)
        : mConnectionMode(0)
        , mThreadIfStatus(0)
        , mAvailability(0)
        , mBbrIsActive(0)
        , mBbrIsPrimary(0)
    {
    }

    uint32_t ToUint32(void) const
    {
        uint32_t bitmap = 0;

        bitmap |= mConnectionMode << 0;
        bitmap |= mThreadIfStatus << 3;
        bitmap |= mAvailability << 5;
        bitmap |= mBbrIsActive << 7;
        bitmap |= mBbrIsPrimary << 8;

        return bitmap;
    }
};


#if OTBR_ENABLE_NCP_OPENTHREAD
static const uint16_t kThreadVersion11 = 2; ///< Thread Version 1.1
static const uint16_t kThreadVersion12 = 3; ///< Thread Version 1.2
#endif

static const size_t kMaxSizeOfPacket          = 1500;             ///< Max size of packet in bytes.

/**
 * UDP ports
 *
 */
enum
{
    kBorderAgentUdpPort = 49191, ///< Thread commissioning port.
};


BorderAgent::BorderAgent(Ncp::Controller *aNcp, Mdns::Publisher &aPublisher)
#if OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO
    : mPublisher(aPublisher)
#else
    : mPublisher(NULL)
#endif
    , mNcp(aNcp)
#if OTBR_ENABLE_NCP_WPANTUND
    , mSocket(-1)
#endif
    , mThreadStarted(false)
{
}

void BorderAgent::Init(void)
{
    memset(mNetworkName, 0, sizeof(mNetworkName));
    memset(mExtPanId, 0, sizeof(mExtPanId));
    mExtPanIdInitialized = false;
    mThreadVersion       = 0;

#if OTBR_ENABLE_NCP_WPANTUND
    mNcp->On(Ncp::kEventUdpForwardStream, SendToCommissioner, this);
#endif
#if OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO
    mNcp->On(Ncp::kEventExtPanId, HandleExtPanId, this);
    mNcp->On(Ncp::kEventNetworkName, HandleNetworkName, this);
    mNcp->On(Ncp::kEventThreadVersion, HandleThreadVersion, this);
#endif
    mNcp->On(Ncp::kEventThreadState, HandleThreadState, this);
    mNcp->On(Ncp::kEventPSKc, HandlePSKc, this);

    otbrLogResult(mNcp->RequestEvent(Ncp::kEventThreadState), "Check if Thread is up");
    otbrLogResult(mNcp->RequestEvent(Ncp::kEventPSKc), "Check if PSKc is initialized");
}

otbrError BorderAgent::Start(void)
{
    otbrError error = OTBR_ERROR_NONE;

    VerifyOrExit(mThreadStarted && mPSKcInitialized, errno = EAGAIN, error = OTBR_ERROR_ERRNO);

    // In case we didn't receive Thread down event.
    Stop();

#if OTBR_ENABLE_NCP_WPANTUND
    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port   = htons(kBorderAgentUdpPort);

    mSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    VerifyOrExit(mSocket != -1, error = OTBR_ERROR_ERRNO);
    VerifyOrExit(bind(mSocket, reinterpret_cast<struct sockaddr *>(&sin6), sizeof(sin6)) == 0,
                 error = OTBR_ERROR_ERRNO);
#endif

#if OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO
    SuccessOrExit(error = mNcp->RequestEvent(Ncp::kEventNetworkName));
    SuccessOrExit(error = mNcp->RequestEvent(Ncp::kEventExtPanId));

// Currently supports only NCP_OPENTHREAD
#if OTBR_ENABLE_NCP_OPENTHREAD
    SuccessOrExit(error = mNcp->RequestEvent(Ncp::kEventThreadVersion));
#endif // OTBR_ENABLE_NCP_OPENTHREAD
    StartPublishService();
#endif // OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO

    // Suppress unused warning of label exit
    ExitNow();

exit:
    otbrLogResult(error, "Start Thread Border Agent");
    return error;
}

void BorderAgent::Stop(void)
{
#if OTBR_ENABLE_NCP_WPANTUND
    if (mSocket != -1)
    {
        close(mSocket);
        mSocket = -1;
    }
#endif // OTBR_ENABLE_NCP_WPANTUND

    otbrLogInfo("Stop Thread Border Agent");
    UnpublishMeshCopService();
}

void BorderAgent::UnpublishMeshCopService(void)
{
    otbrLogInfo("Unpublish meshcop service %s.%s.local", mServiceInstanceName.c_str(), kBorderAgentServiceType);

    mPublisher.UnpublishService(mServiceInstanceName, kBorderAgentServiceType, [this](otbrError aError) {
        otbrLogResult(aError, "Result of unpublish meshcop service %s.%s.local", mServiceInstanceName.c_str(),
                      kBorderAgentServiceType);
    });
}

void BorderAgent::PublishMeshCopService(void)
{
    StateBitmap              state;
    uint32_t                 stateUint32;
    otInstance              *instance    = mNcp.GetInstance();
    const otExtendedPanId   *extPanId    = otThreadGetExtendedPanId(instance);
    const otExtAddress      *extAddr     = otLinkGetExtendedAddress(instance);
    const char              *networkName = otThreadGetNetworkName(instance);
    Mdns::Publisher::TxtList txtList{{"rv", "1"}};
    Mdns::Publisher::TxtData txtData;
    int                      port;
    otbrError                error;

    OTBR_UNUSED_VARIABLE(error);

    otbrLogInfo("Publish meshcop service %s.%s.local.", mServiceInstanceName.c_str(), kBorderAgentServiceType);

#if OTBR_ENABLE_PUBLISH_MESHCOP_BA_ID
    {
        otError         error;
        otBorderAgentId id;

        error = otBorderAgentGetId(instance, &id);
        if (error == OT_ERROR_NONE)
        {
            txtList.emplace_back("id", id.mId, sizeof(id));
        }
        else
        {
            otbrLogWarning("Failed to retrieve Border Agent ID: %s", otThreadErrorToString(error));
        }
    }
#endif

    if (!mVendorOui.empty())
    {
        txtList.emplace_back("vo", mVendorOui.data(), mVendorOui.size());
    }
    if (!mVendorName.empty())
    {
        txtList.emplace_back("vn", mVendorName.c_str());
    }
    if (!mProductName.empty())
    {
        txtList.emplace_back("mn", mProductName.c_str());
    }
    txtList.emplace_back("nn", networkName);
    txtList.emplace_back("xp", extPanId->m8, sizeof(extPanId->m8));
    txtList.emplace_back("tv", mNcp.GetThreadVersion());

    // "xa" stands for Extended MAC Address (64-bit) of the Thread Interface of the Border Agent.
    txtList.emplace_back("xa", extAddr->m8, sizeof(extAddr->m8));

    state       = GetStateBitmap(*instance);
    stateUint32 = htobe32(state.ToUint32());
    txtList.emplace_back("sb", reinterpret_cast<uint8_t *>(&stateUint32), sizeof(stateUint32));

    if (state.mThreadIfStatus == kThreadIfStatusActive)
    {
        uint32_t partitionId;

        AppendActiveTimestampTxtEntry(*instance, txtList);
        partitionId = otThreadGetPartitionId(instance);
        txtList.emplace_back("pt", reinterpret_cast<uint8_t *>(&partitionId), sizeof(partitionId));
    }

#if OTBR_ENABLE_BACKBONE_ROUTER
    AppendBbrTxtEntries(*instance, state, txtList);
#endif
#if OTBR_ENABLE_BORDER_ROUTING
    AppendOmrTxtEntry(*instance, txtList);
#endif
#if OTBR_ENABLE_DBUS_SERVER
    AppendVendorTxtEntries(mMeshCopTxtUpdate, txtList);
#endif

    if (otBorderAgentGetState(instance) != OT_BORDER_AGENT_STATE_STOPPED)
    {
        port = otBorderAgentGetUdpPort(instance);
    }
    else
    {
        // When thread interface is not active, the border agent is not started, thus it's not listening to any port and
        // not handling requests. In such situation, we use a dummy port number for publishing the MeshCoP service to
        // advertise the status of the border router. One can learn the thread interface status from `sb` entry so it
        // doesn't have to send requests to the dummy port when border agent is not running.
        port = kBorderAgentServiceDummyPort;
    }

    error = Mdns::Publisher::EncodeTxtData(txtList, txtData);
    assert(error == OTBR_ERROR_NONE);

    mPublisher.PublishService(/* aHostName */ "", mServiceInstanceName, kBorderAgentServiceType,
                              Mdns::Publisher::SubTypeList{}, port, txtData, [this](otbrError aError) {
                                  if (aError == OTBR_ERROR_ABORTED)
                                  {
                                      // OTBR_ERROR_ABORTED is thrown when an ongoing service registration is
                                      // cancelled. This can happen when the meshcop service is being updated
                                      // frequently. To avoid false alarms, it should not be logged like a real error.
                                      otbrLogInfo("Cancelled previous publishing meshcop service %s.%s.local",
                                                  mServiceInstanceName.c_str(), kBorderAgentServiceType);
                                  }
                                  else
                                  {
                                      otbrLogResult(aError, "Result of publish meshcop service %s.%s.local",
                                                    mServiceInstanceName.c_str(), kBorderAgentServiceType);
                                  }
                                  if (aError == OTBR_ERROR_DUPLICATED)
                                  {
                                      // Try to unpublish current service in case we are trying to register
                                      // multiple new services simultaneously when the original service name
                                      // is conflicted.
                                      UnpublishMeshCopService();
                                      mServiceInstanceName = GetAlternativeServiceInstanceName();
                                      PublishMeshCopService();
                                  }
                              });
}

void BorderAgent::UpdateMeshCopService(void)
{
    VerifyOrExit(IsEnabled());
    VerifyOrExit(mPublisher.IsStarted());
    PublishMeshCopService();

exit:
    return;
}


void BorderAgent::HandleMdnsState(Mdns::Publisher::State aState)
{
    VerifyOrExit(IsEnabled());

    switch (aState)
    {
    case Mdns::Publisher::State::kReady:
        UpdateMeshCopService();
        break;
    default:
        otbrLogWarning("mDNS publisher not available!");
        break;
    }
exit:
    return;
}

#if OTBR_ENABLE_NCP_WPANTUND
void BorderAgent::SendToCommissioner(void *aContext, int aEvent, va_list aArguments)
{
    struct sockaddr_in6 sin6;
    const uint8_t *     packet      = va_arg(aArguments, const uint8_t *);
    uint16_t            length      = static_cast<uint16_t>(va_arg(aArguments, unsigned int));
    uint16_t            peerPort    = static_cast<uint16_t>(va_arg(aArguments, unsigned int));
    const in6_addr *    addr        = va_arg(aArguments, const in6_addr *);
    uint16_t            sockPort    = static_cast<uint16_t>(va_arg(aArguments, unsigned int));
    BorderAgent *       borderAgent = static_cast<BorderAgent *>(aContext);

    (void)aEvent;
    assert(aEvent == Ncp::kEventUdpForwardStream);
    VerifyOrExit(sockPort == kBorderAgentUdpPort);
    VerifyOrExit(borderAgent->mSocket != -1);

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    memcpy(sin6.sin6_addr.s6_addr, addr->s6_addr, sizeof(sin6.sin6_addr));
    sin6.sin6_port = htons(peerPort);

    {
        ssize_t sent =
            sendto(borderAgent->mSocket, packet, length, 0, reinterpret_cast<const sockaddr *>(&sin6), sizeof(sin6));
        VerifyOrExit(sent == static_cast<ssize_t>(length), perror("send to commissioner"));
    }

    otbrLog(OTBR_LOG_DEBUG, OTBR_LOG_TAG, "Sent to commissioner");

exit:
    return;
}
#endif // OTBR_ENABLE_NCP_WPANTUND

void BorderAgent::UpdateFdSet(fd_set & aReadFdSet,
                              fd_set & aWriteFdSet,
                              fd_set & aErrorFdSet,
                              int &    aMaxFd,
                              timeval &aTimeout)
{
    if (mPublisher != NULL)
    {
        mPublisher.UpdateFdSet(aReadFdSet, aWriteFdSet, aErrorFdSet, aMaxFd, aTimeout);
    }

#if OTBR_ENABLE_NCP_WPANTUND
    if (mSocket != -1)
    {
        FD_SET(mSocket, &aReadFdSet);

        if (mSocket > aMaxFd)
        {
            aMaxFd = mSocket;
        }
    }

#endif // OTBR_ENABLE_NCP_WPANTUND
}

void BorderAgent::Process(const fd_set &aReadFdSet, const fd_set &aWriteFdSet, const fd_set &aErrorFdSet)
{
    if (mPublisher != NULL)
    {
        mPublisher.Process(aReadFdSet, aWriteFdSet, aErrorFdSet);
    }

#if OTBR_ENABLE_NCP_WPANTUND
    uint8_t             packet[kMaxSizeOfPacket];
    struct sockaddr_in6 sin6;
    ssize_t             len     = sizeof(packet);
    socklen_t           socklen = sizeof(sin6);

    VerifyOrExit(mSocket != -1 && FD_ISSET(mSocket, &aReadFdSet));

    len = recvfrom(mSocket, packet, sizeof(packet), 0, reinterpret_cast<struct sockaddr *>(&sin6), &socklen);
    VerifyOrExit(len > 0);

    mNcp->UdpForwardSend(packet, static_cast<uint16_t>(len), ntohs(sin6.sin6_port), sin6.sin6_addr,
                         kBorderAgentUdpPort);

exit:
#endif
    return;
}

#if OTBR_ENABLE_NCP_OPENTHREAD
static const char *ThreadVersionToString(uint16_t aThreadVersion)
{
    switch (aThreadVersion)
    {
    case kThreadVersion11:
        return "1.1.1";
    case kThreadVersion12:
        return "1.2.0";
    default:
        otbrLog(OTBR_LOG_ERR, "unexpected thread version %hu", aThreadVersion);
        abort();
    }
}
#endif
/*
void BorderAgent::PublishService(void)
{
    char xpanid[sizeof(mExtPanId) * 2 + 1];

    assert(mNetworkName[0] != '\0');
    assert(mExtPanIdInitialized);
    Utils::Bytes2Hex(mExtPanId, sizeof(mExtPanId), xpanid);

#if OTBR_ENABLE_NCP_OPENTHREAD
    assert(mThreadVersion != 0);
    mPublisher.PublishService(kBorderAgentUdpPort, mNetworkName, kBorderAgentServiceType, "nn", mNetworkName, "xp",
                               xpanid, "tv", ThreadVersionToString(mThreadVersion), NULL);
#else
    mPublisher.PublishService(kBorderAgentUdpPort, mNetworkName, kBorderAgentServiceType, "nn", mNetworkName, "xp",
                               xpanid, NULL);
#endif
}

void BorderAgent::StartPublishService(void)
{
    VerifyOrExit(mNetworkName[0] != '\0');
    VerifyOrExit(mExtPanIdInitialized);
#if OTBR_ENABLE_NCP_OPENTHREAD
    VerifyOrExit(mThreadVersion != 0);
#endif

    if (mPublisher.IsStarted())
    {
        PublishService();
    }
    else
    {
        mPublisher.Start();
    }

exit:
    otbrLog(OTBR_LOG_INFO, OTBR_LOG_TAG, "Start publishing service");
}

void BorderAgent::StopPublishService(void)
{
    VerifyOrExit(mPublisher != NULL);

    if (mPublisher.IsStarted())
    {
        mPublisher.Stop();
    }

exit:
    otbrLog(OTBR_LOG_INFO, OTBR_LOG_TAG, "Stop publishing service");
}

void BorderAgent::SetNetworkName(const char *aNetworkName)
{
    strcpy_safe(mNetworkName, sizeof(mNetworkName), aNetworkName);

#if OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO
    if (mThreadStarted)
    {
        // Restart publisher to publish new service name.
        mPublisher.Stop();
        StartPublishService();
    }
#endif
}

void BorderAgent::SetExtPanId(const uint8_t *aExtPanId)
{
    memcpy(mExtPanId, aExtPanId, sizeof(mExtPanId));
    mExtPanIdInitialized = true;
#if OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO
    if (mThreadStarted)
    {
        StartPublishService();
    }
#endif
}

void BorderAgent::SetThreadVersion(uint16_t aThreadVersion)
{
    mThreadVersion = aThreadVersion;
#if OTBR_ENABLE_MDNS_AVAHI || OTBR_ENABLE_MDNS_MDNSSD || OTBR_ENABLE_MDNS_MOJO
    if (mThreadStarted)
    {
        StartPublishService();
    }
#endif
}
*/
void BorderAgent::HandlePSKc(void *aContext, int aEvent, va_list aArguments)
{
    assert(aEvent == Ncp::kEventPSKc);

    static_cast<BorderAgent *>(aContext)->HandlePSKc(va_arg(aArguments, const uint8_t *));
}

void BorderAgent::HandlePSKc(const uint8_t *aPSKc)
{
    mPSKcInitialized = false;

    for (size_t i = 0; i < kSizePSKc; ++i)
    {
        if (aPSKc[i] != 0)
        {
            mPSKcInitialized = true;
            break;
        }
    }

    if (mPSKcInitialized)
    {
        Start();
    }
    else
    {
        Stop();
    }

    otbrLog(OTBR_LOG_INFO, OTBR_LOG_TAG, "PSKc is %s", (mPSKcInitialized ? "initialized" : "not initialized"));
}

void BorderAgent::HandleThreadState(bool aStarted)
{
    VerifyOrExit(mThreadStarted != aStarted);

    mThreadStarted = aStarted;

    if (aStarted)
    {
        SuccessOrExit(mNcp->RequestEvent(Ncp::kEventPSKc));
        Start();
    }
    else
    {
        Stop();
    }

exit:
    otbrLog(OTBR_LOG_INFO, OTBR_LOG_TAG, "Thread is %s", (aStarted ? "up" : "down"));
}

void BorderAgent::HandleThreadState(void *aContext, int aEvent, va_list aArguments)
{
    assert(aEvent == Ncp::kEventThreadState);

    int started = va_arg(aArguments, int);
    static_cast<BorderAgent *>(aContext)->HandleThreadState(started);
}

void BorderAgent::HandleNetworkName(void *aContext, int aEvent, va_list aArguments)
{
    assert(aEvent == Ncp::kEventNetworkName);

    const char *networkName = va_arg(aArguments, const char *);
    static_cast<BorderAgent *>(aContext)->SetNetworkName(networkName);
}

void BorderAgent::HandleExtPanId(void *aContext, int aEvent, va_list aArguments)
{
    assert(aEvent == Ncp::kEventExtPanId);

    const uint8_t *xpanid = va_arg(aArguments, const uint8_t *);
    static_cast<BorderAgent *>(aContext)->SetExtPanId(xpanid);
}

void BorderAgent::HandleThreadVersion(void *aContext, int aEvent, va_list aArguments)
{
    assert(aEvent == Ncp::kEventThreadVersion);

    // `uint16_t` has been promoted to `int`.
    uint16_t threadVersion = static_cast<uint16_t>(va_arg(aArguments, int));
    static_cast<BorderAgent *>(aContext)->SetThreadVersion(threadVersion);
}

} // namespace otbr
