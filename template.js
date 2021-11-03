/// <reference path="./extra/JsProvider.d.ts"/>

function exec(cmdString) {
  // have to use dx @$scriptContents to have namespace
  const control = host.namespace.Debugger.Utility.Control

  return control.ExecuteCommand(cmdString)
}

function log(msg) {
  return host.diagnostics.debugLog(msg)
}

log("script loaded!")

// dx @$scriptContents.exec("lma @$exentry")