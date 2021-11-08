/// <reference path="../extra/JsProvider.d.ts"/>

/*
 .scriptunload m:\script\windbg\scripts\mem-leak-auto-analysis.js
 .scriptload m:\script\windbg\scripts\mem-leak-auto-analysis.js
 dx @$scriptContents.runCommand("!heap -s")
 or 
  .scriptrun m:\script\windbg\scripts\mem-leak-auto-analysis.js
 */

function log(message) {
  host.diagnostics.debugLog(message);
}
function logLine(message) {
  host.diagnostics.debugLog(message + '\n');
}

function printResult(output) {
  for (var line of output) {
    logLine(line);
  }
}

function run(command, log = true) {
  if (log) logLine(`>>>: ${command}`);
  const ctl = host.namespace.Debugger.Utility.Control;
  const output = ctl.ExecuteCommand(command);
  return output;
}

function invokeScript() {
  const heapSummary = run('!heap -s')
  /**
  
  
  ************************************************************************************************************************
                                                NT HEAP STATS BELOW
  ************************************************************************************************************************
  NtGlobalFlag enables following debugging aids for new heaps:
      stack back traces
  LFH Key                   : 0x3b896c249c677c2a
  Termination on corruption : ENABLED
            Heap     Flags   Reserv  Commit  Virt   Free  List   UCR  Virt  Lock  Fast
                              (k)     (k)    (k)     (k) length      blocks cont. heap
  -------------------------------------------------------------------------------------
  0000019986690000 08000002   65128  64284  64928     87   246     8   45     20   LFH
  0000019984c50000 08008000      64      4     64      2     1     1    0      0
  0000019986660000 08001002    1280    128   1080     38     8     2    0      1   LFH
  0000019986800000 08001002    1280    244   1080    140     9     2    0      0   LFH
  0000019986d50000 08001002    1280    120   1080      3    16     2    0      0   LFH
  0000019986d40000 08041002      60      8     60      5     1     1    0      0
  000001999fdf0000 08041002    1280    124   1080     18     4     2    0      0   LFH
  -------------------------------------------------------------------------------------
     */
  printResult(heapSummary);
  const firstHeap = heapSummary[12].split(' ').filter(i => i.trim() !== '')
  const firstHeapAddress = firstHeap[0];
  // logLine(firstHeapAddress);
  const statOf1st = run(`!heap -stat -h ${firstHeapAddress}`)
  printResult(statOf1st);
  const heapResultOfSize10217 = run(`!heap -flt s 10217`);
  printResult(heapResultOfSize10217)
  /*
0:000> !heap -flt s 10217
    _HEAP @ 19986690000
              HEAP_ENTRY Size Prev Flags            UserPtr UserSize - state
        00000199a56465b0 1024 0000  [00]   00000199a56465e0    10217 - (busy)
          unknown!printable
        00000199a56567f0 1024 1024  [00]   00000199a5656820    10217 - (busy)
          unknown!printable
        00000199a56aba90 1024 1024  [00]   00000199a56abac0    10217 - (busy)
          unknown!printable
        00000199a56bbcd0 1024 1024  [00]   00000199a56bbd00    10217 - (busy)
          unknown!printable
        00000199a56cdf50 1024 1024  [00]   00000199a56cdf80    10217 - (busy)
          unknown!printable
        00000199a56de190 1024 1024  [00]   00000199a56de1c0    10217 - (busy)
            _HEAP @ 19984c50000
    _HEAP @ 19986660000
    _HEAP @ 19986800000
*/

  const blocksOfSize10217 = [];
  for (const line of heapResultOfSize10217) {
    const validLine = /\[\d+\]\s+(\d\w+)/.exec(line);
    if (validLine) {
      const userPtr = validLine[1];
      blocksOfSize10217.push([line, userPtr]);
    }
  }

  const sampleSize = 50;
  const indexesChosen = [];
  const statisticDictionary = {}
  const candidateSize = blocksOfSize10217.length;
  const statisticSize = Math.min(sampleSize, candidateSize)
  logLine(`${statisticSize}/${candidateSize} items to analysis......`)

  for (let i = 0; i < statisticSize; i++) {
    let index = NaN
    do {
      index = Math.floor((Math.random() * blocksOfSize10217.length));
    } while (indexesChosen.includes(index))

    indexesChosen.push(index);
    const userPtr = blocksOfSize10217[index][1];
    const callStackWhenHeapAllocating = run(`!heap -p -a ${userPtr}`)
    // printRst(stack);
    // logLine('_____________________________________')

    /*
    >>>: !heap -p -a 00000199abe8b6c0
      address 00000199abe8b6c0 found in
      _HEAP @ 19986690000
                HEAP_ENTRY Size Prev Flags            UserPtr UserSize - state
          00000199abe8b690 1024 0000  [00]   00000199abe8b6c0    10217 - (busy)
            unknown!printable
          7ff8995b07d3 ntdll!RtlpCallInterceptRoutine+0x000000000000003f
          7ff899543be4 ntdll!RtlpAllocateHeapInternal+0x0000000000001164
          7ff8961ddb6e ucrtbase!_calloc_base+0x000000000000004e
          7ff814275d5b nddscore!RTIOsapiHeap_reallocateMemoryInternal+0x00000000000002db
          7ff81418affc nddscore!MIGGenerator_beginMessage+0x000000000000071c
          7ff81418aa62 nddscore!MIGGenerator_beginMessage+0x0000000000000182
          7ff814163857 nddscore!COMMENDSrWriterService_new+0x00000000000085b7
          7ff8141869c7 nddscore!MIGInterpreter_parse+0x00000000000006a7
          7ff81412185f nddscore!COMMENDPassiveFacade_processMessage+0x000000000000046f
          7ff896240106 ucrtbase!thread_start<void (__cdecl*)(void * __ptr64)>+0x00000000000000a6
          7ff8990784d4 kernel32!BaseThreadInitThunk+0x0000000000000014
          7ff899571781 ntdll!RtlUserThreadStart+0x0000000000000021
     
     
     
        */
    const key = [...callStackWhenHeapAllocating].slice(5).filter(l => l.trim() !== '').join('\n');
    const value = statisticDictionary[key];
    if (!value) statisticDictionary[key] = []
    statisticDictionary[key].push(userPtr)
  }

  const result = Object.entries(statisticDictionary);

  result.sort((a, b) => a[1].length - b[1].length)

  result.forEach(([stack, userPointers]) => {
    const allocationTimesOfSameCallingStack = userPointers.length;
    logLine(`[${allocationTimesOfSameCallingStack}/${statisticSize}: ${(allocationTimesOfSameCallingStack / statisticSize).toFixed(3)}]: ${userPointers.join(',')}`)
    logLine(stack);
  })

  if (statisticSize !== candidateSize) {
    logLine(`items:${statisticSize} randomly chosen from ${candidateSize}.`);
  } else {
    logLine(`items: ${statisticSize}.`)
  }

}

/*
run PrestoGateway then run:
 .\gflags.exe /i Slb.Planck.Core.PrestoGateway.Service.exe +ust
create dump to analysis:
sl C:\Program Files\Windows Kits\10\Debuggers\x64
robocopy \\tsclient\M\Script\windbg\scripts\ . presto-gateway-mem-leak-auto-analysis.js
.scriptrun presto-gateway-mem-leak-auto-analysis.js

*/