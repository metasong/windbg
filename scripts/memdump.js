/*
    How to use :

    .load jsprovider.dll
    .scriptload memdump.js
    
    bp MSVCR120D!free ".scriptrun memdump.js"
    bp MSVCR120D!malloc ".scriptrun memdump.js"
*/
/// <reference path="../extra/JsProvider.d.ts"/>
"use strict";

function displayMessage(message)
{
    host.diagnostics.debugLog(message);
}

function getCallStackAsString()
{
    var ret = "";
    var curThread = host.currentThread;
    for (var frame of curThread.Stack.Frames)
    {
        ret += (frame.toString() + "\n");
    }
    return ret;
}

function runCommand(command)
{
    var ret = "";
    displayMessage("Executing : " + command + "\n");
    var ctl = host.namespace.Debugger.Utility.Control;   
    var output = ctl.ExecuteCommand(command);
    for (var line of output)
    {
        ret = line;
        break;
    }
    return ret;
}

function getCurrentFunctionName()
{
    var currentThread = host.currentThread;
    var currentFunctionName = currentThread.Stack.Frames[0].toString();
    return currentFunctionName;
}

function getFirstArgument()
{
    var ret = runCommand(".printf \"%d\", dwo(esp+4)");
    return ret;
}

function handleMalloc()
{
    var allocSize = getFirstArgument();
    displayMessage("\n\nmalloc called with size : "+ allocSize  +  "\n\n");
}

function handleFree()
{
    var address = getFirstArgument();
    displayMessage("\n\nfree called for address : "+ address  +  "\n\n");
}

function invokeScript()
{
    var ctl = host.namespace.Debugger.Utility.Control;
    
    var currentFunctionName = getCurrentFunctionName();
    if( currentFunctionName.includes("free"))
    {
        handleFree();
    }
    else if( currentFunctionName.includes("malloc") )
    {
        handleMalloc();
    }
    ctl.ExecuteCommand("gc");
}