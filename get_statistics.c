#include <librdi.h>
#include <stdio.h>

#define NUM_OF_DEVICES 1
#define NUM_OF_PORTS 4

int main(int argc, char **argv)
{
   int device,port;
   rdi_stat_cnt_t statistics_struct;
   
   for(device = 0; device <= NUM_OF_DEVICES; device++)
   {
      for(port = 0; port < NUM_OF_PORTS; port++)
      {
        if(rdi_get_stat(device, port,&statistics_struct, RDI_FLCM_DEV) < 0)
        {
          printf("Device statistics for device %d port %d is not available\n",device,port);
        }
        else
        {
     printf("RDI device statistics:--------------------------------------\n");
     printf("DEVICE[%d]PORT[%d]-----------\n", device,port);
     printf("cntRxUcstPkts--------------%lld\n", statistics_struct.rdif.cntRxUcstPkts);
     printf("cntRxUcstPktsNonIP---------%lld\n",statistics_struct.rdif.cntRxUcstPkts);
     printf("cntRxUcstPktsIPv4-----------%lld\n",statistics_struct.rdif.cntRxUcstPktsIPv4);
     printf("cntRxUcstPktsIPv6-----------%lld\n",statistics_struct.rdif.cntRxUcstPktsIPv6);
     printf("cntRxBcstPkts---------------%lld\n",statistics_struct.rdif.cntRxBcstPkts);
     printf("cntRxBcstPkts---------------%lld\n",statistics_struct.rdif.cntRxBcstPkts);
     printf("cntRxBcstPktsNonIP----------%lld\n",statistics_struct.rdif.cntRxBcstPktsNonIP);
     printf("cntRxBcstPktsIPv4-----------%lld\n",statistics_struct.rdif.cntRxBcstPktsIPv4);
     printf("cntRxBcstPktsIPv6-----------%lld\n",statistics_struct.rdif.cntRxBcstPktsIPv6);
     printf("cntRxMcstPkts---------------%lld\n",statistics_struct.rdif.cntRxMcstPkts);
     printf("cntRxMcstPktsNonIP----------%lld\n",statistics_struct.rdif.cntRxMcstPktsNonIP);
     printf("cntRxMcstPktsIPv4-----------%lld\n",statistics_struct.rdif.cntRxMcstPktsIPv4);
     printf("cntRxMcstPktsIPv6-----------%lld\n",statistics_struct.rdif.cntRxMcstPktsIPv6);
     printf("cntRxPausePkts--------------%lld\n",statistics_struct.rdif.cntRxPausePkts);
     printf("cntRxCBPausePkts------------%lld\n",statistics_struct.rdif.cntRxCBPausePkts);
     printf("cntRxFCSErrors--------------%lld\n",statistics_struct.rdif.cntRxFCSErrors);
     printf("cntRxSymbolErrors-----------%lld\n",statistics_struct.rdif.cntRxSymbolErrors);
     printf("cntRxFrameSizeErrors--------%lld\n",statistics_struct.rdif.cntRxFrameSizeErrors);
     printf("cntRxMinTo63Pkts------------%lld\n",statistics_struct.rdif.cntRxMinTo63Pkts);
     printf("cntRx64Pkts-----------------%lld\n",statistics_struct.rdif.cntRx64Pkts);
     printf("cntRx65to127Pkts------------%lld\n",statistics_struct.rdif.cntRx65to127Pkts);
     printf("cntRx128to255Pkts-----------%lld\n",statistics_struct.rdif.cntRx128to255Pkts);
     printf("cntRx256to511Pkts-----------%lld\n",statistics_struct.rdif.cntRx256to511Pkts);
     printf("cntRx512to1023Pkts----------%lld\n",statistics_struct.rdif.cntRx512to1023Pkts);
     printf("cntRx1024to1522Pkts---------%lld\n",statistics_struct.rdif.cntRx1024to1522Pkts);
     printf("cntRx1523to2047Pkts---------%lld\n",statistics_struct.rdif.cntRx1523to2047Pkts);
     printf("cntRx2048to4095Pkts---------%lld\n",statistics_struct.rdif.cntRx2048to4095Pkts);
     printf("cntRx4096to8191Pkts---------%lld\n",statistics_struct.rdif.cntRx4096to8191Pkts);
     printf("cntRx8192to10239Pkts--------%lld\n",statistics_struct.rdif.cntRx8192to10239Pkts);
     printf("cntRx10240toMaxPkts---------%lld\n",statistics_struct.rdif.cntRx10240toMaxPkts);
     printf("cntRxFragmentPkts-----------%lld\n",statistics_struct.rdif.cntRxFragmentPkts);
     printf("cntRxUndersizedPkts---------%lld\n",statistics_struct.rdif.cntRxUndersizedPkts);
     printf("cntRxJabberPkts-------------%lld\n",statistics_struct.rdif.cntRxJabberPkts);
     printf("cntRxOversizedPkts----------%lld\n",statistics_struct.rdif.cntRxOversizedPkts);
     printf("cntRxGoodOctets-------------%lld\n",statistics_struct.rdif.cntRxGoodOctets);
     printf("cntRxOctetsNonIp------------%lld\n",statistics_struct.rdif.cntRxOctetsNonIp);
     printf("cntRxOctetsIPv4-------------%lld\n",statistics_struct.rdif.cntRxOctetsIPv4);
     printf("cntRxOctetsIPv6-------------%lld\n",statistics_struct.rdif.cntRxOctetsIPv6);
     printf("cntRxBadOctets--------------%lld\n",statistics_struct.rdif.cntRxBadOctets);
     printf("cntRxPriorityPkts-----------%lld\n",statistics_struct.rdif.cntRxPriorityPkts);
     printf("cntRxPriorityOctets---------%lld\n",statistics_struct.rdif.cntRxPriorityOctets);
     printf("cntTxUcstPkts---------------%lld\n",statistics_struct.rdif.cntTxUcstPkts);
     printf("cntTxBcstPkts---------------%lld\n",statistics_struct.rdif.cntTxBcstPkts);
     printf("cntTxMcstPkts---------------%lld\n",statistics_struct.rdif.cntTxMcstPkts);
     printf("cntTxPausePkts--------------%lld\n",statistics_struct.rdif.cntTxPausePkts);
     printf("cntTxFCSErroredPkts---------%lld\n",statistics_struct.rdif.cntTxFCSErroredPkts);
     printf("cntTxErrorDropPkts----------%lld\n",statistics_struct.rdif.cntTxErrorDropPkts);
     printf("cntTxTimeOutPkts------------%lld\n",statistics_struct.rdif.cntTxTimeOutPkts);
     printf("cntTxLoopbackPkts-----------%lld\n",statistics_struct.rdif.cntTxLoopbackPkts);
     printf("cntTxMinTo63Pkts------------%lld\n",statistics_struct.rdif.cntTxMinTo63Pkts);
     printf("cntTx64Pkts-----------------%lld\n",statistics_struct.rdif.cntTx64Pkts);
     printf("cntTx65to127Pkts------------%lld\n",statistics_struct.rdif.cntTx65to127Pkts);
     printf("cntTx128to255Pkts-----------%lld\n",statistics_struct.rdif.cntTx128to255Pkts);
     printf("cntTx256to511Pkts-----------%lld\n",statistics_struct.rdif.cntTx256to511Pkts);
     printf("cntTx512to1023Pkts----------%lld\n",statistics_struct.rdif.cntTx512to1023Pkts);
     printf("cntTx1024to1522Pkts---------%lld\n",statistics_struct.rdif.cntTx1024to1522Pkts);
     printf("cntTx1523to2047Pkts---------%lld\n",statistics_struct.rdif.cntTx1523to2047Pkts);
     printf("cntTx2048to4095Pkts---------%lld\n",statistics_struct.rdif.cntTx2048to4095Pkts);
     printf("cntTx4096to8191Pkts---------%lld\n",statistics_struct.rdif.cntTx4096to8191Pkts);
     printf("cntTx8192to10239Pkts--------%lld\n",statistics_struct.rdif.cntTx8192to10239Pkts);
     printf("cntTx10240toMaxPkts---------%lld\n",statistics_struct.rdif.cntTx10240toMaxPkts);
     printf("cntTxOctets-----------------%lld\n",statistics_struct.rdif.cntTxOctets);
     printf("cntTxErrorOctets------------%lld\n",statistics_struct.rdif.cntTxErrorOctets);
     printf("cntTxCMDropPkts-------------%lld\n",statistics_struct.rdif.cntTxCMDropPkts);
     printf("cntFIDForwardedPkts---------%lld\n",statistics_struct.rdif.cntFIDForwardedPkts);
     printf("cntFloodForwardedPkts-------%lld\n",statistics_struct.rdif.cntFloodForwardedPkts);
     printf("cntSpeciallyHandledPkts-----%lld\n",statistics_struct.rdif.cntSpeciallyHandledPkts);
     printf("cntParseErrDropPkts---------%lld\n",statistics_struct.rdif.cntParseErrDropPkts);
     printf("cntParityErrorPkts----------%lld\n",statistics_struct.rdif.cntParityErrorPkts);
     printf("cntTrappedPkts--------------%lld\n",statistics_struct.rdif.cntTrappedPkts);
     printf("cntPauseDropPkts------------%lld\n",statistics_struct.rdif.cntPauseDropPkts);
     printf("cntSTPDropPkts--------------%lld\n",statistics_struct.rdif.cntSTPDropPkts);
     printf("cntReservedTrapPkts---------%lld\n",statistics_struct.rdif.cntReservedTrapPkts);
     printf("cntSecurityViolationPkts----%lld\n",statistics_struct.rdif.cntSecurityViolationPkts);
     printf("cntVLANTagDropPkts----------%lld\n",statistics_struct.rdif.cntVLANTagDropPkts);
     printf("cntVLANIngressBVPkts--------%lld\n",statistics_struct.rdif.cntVLANIngressBVPkts);
     printf("cntVLANEgressBVPkts---------%lld\n",statistics_struct.rdif.cntVLANEgressBVPkts);
     printf("cntGlortMissDropPkts--------%lld\n",statistics_struct.rdif.cntGlortMissDropPkts);
     printf("cntFFUDropPkts--------------%lld\n",statistics_struct.rdif.cntFFUDropPkts);
     printf("cntPolicerDropPkts----------%lld\n",statistics_struct.rdif.cntPolicerDropPkts);
     printf("cntTTLDropPkts--------------%lld\n",statistics_struct.rdif.cntTTLDropPkts);
     printf("cntCmPrivDropPkts-----------%lld\n",statistics_struct.rdif.cntCmPrivDropPkts);
     printf("cntSmp0DropPkts-------------%lld\n",statistics_struct.rdif.cntSmp0DropPkts);
     printf("cntSmp1DropPkts-------------%lld\n",statistics_struct.rdif.cntSmp1DropPkts);
     printf("cntRxHog0DropPkts-----------%lld\n",statistics_struct.rdif.cntRxHog0DropPkts);
     printf("cntRxHog1DropPkts-----------%lld\n",statistics_struct.rdif.cntRxHog1DropPkts);
     printf("cntTxHog0DropPkts-----------%lld\n",statistics_struct.rdif.cntTxHog0DropPkts);     
     printf("cntRxHog1DropPkts-----------%lld\n",statistics_struct.rdif.cntRxHog1DropPkts);
     printf("cntTxHog0DropPkts-----------%lld\n",statistics_struct.rdif.cntTxHog0DropPkts);
     printf("cntTxHog1DropPkts-----------%lld\n",statistics_struct.rdif.cntTxHog1DropPkts);
     printf("cntRateLimit0DropPkts-------%lld\n",statistics_struct.rdif.cntRateLimit0DropPkts);
     printf("cntRateLimit1DropPkts-------%lld\n",statistics_struct.rdif.cntRateLimit1DropPkts);
     printf("cntBadSmpDropPkts-----------%lld\n",statistics_struct.rdif.cntBadSmpDropPkts);
     printf("cntTriggerDropRedirPkts-----%lld\n",statistics_struct.rdif.cntTriggerDropRedirPkts);
     printf("cntTriggerDropPkts----------%lld\n",statistics_struct.rdif.cntTriggerDropPkts);
     printf("cntTriggerRedirPkts---------%lld\n",statistics_struct.rdif.cntTriggerRedirPkts);
     printf("cntTriggerMirroredPkts------%lld\n",statistics_struct.rdif.cntTriggerMirroredPkts);
     printf("cntBroadcastDropPkts--------%lld\n",statistics_struct.rdif.cntBroadcastDropPkts);
     printf("cntDLFDropPkts--------------%lld\n",statistics_struct.rdif.cntDLFDropPkts);
     printf("cntRxCMDropPkts-------------%lld\n",statistics_struct.rdif.cntRxCMDropPkts);
     printf("cntUnderrunPkts-------------%lld\n",statistics_struct.rdif.cntUnderrunPkts);
     printf("cntOverrunPkts--------------%lld\n",statistics_struct.rdif.cntOverrunPkts);
     printf("cntCorruptedPkts------------%lld\n",statistics_struct.rdif.cntCorruptedPkts);
     printf("cntStatsDropCountTx---------%lld\n",statistics_struct.rdif.cntStatsDropCountTx);
     printf("cntStatsDropCountRx---------%lld\n",statistics_struct.rdif.cntStatsDropCountRx);
     }
    }
  }
   return 0;
}
