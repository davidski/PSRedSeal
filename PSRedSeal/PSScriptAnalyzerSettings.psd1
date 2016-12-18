# PSScriptAnalyzerSettings.psd1
@{
    Severity=@('Error','Warning')
    ExcludeRules=@('PSAvoidUsingCmdletAliases',
      'PSAvoidUsingUserNameAndPassWordParams',
      'PSShouldProcess',
      'PSAvoidUsingPlainTextForPassword',
      'PSUseShouldProcessForStateChangingFunctions')
}