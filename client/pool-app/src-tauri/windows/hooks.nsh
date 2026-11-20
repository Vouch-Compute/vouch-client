; Vouch Compute installer hooks (NSIS, per-user install).
;
; The app starts two helper processes: the agent (pool-core.exe) and, while a job runs, the sandboxed job runner
; (pool-runner.exe). The installer's own "is the app running" check only covers the main program, so the helpers
; are stopped here first; otherwise their files stay locked during an update or uninstall. Only this user's
; processes are touched.

!macro VOUCH_STOP_HELPERS
  nsExec::Exec 'taskkill /F /T /IM pool-core.exe /FI "USERNAME eq $%USERNAME%"'
  Pop $0
  nsExec::Exec 'taskkill /F /T /IM pool-runner.exe /FI "USERNAME eq $%USERNAME%"'
  Pop $0
  Sleep 500
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro VOUCH_STOP_HELPERS
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro VOUCH_STOP_HELPERS
  ; A real uninstall (not the uninstall step of an update) removes the job sandbox's Windows profile. When the
  ; user ticked "Delete the application data", the device keys stored in this computer's security chip are
  ; deleted too; the uninstaller then removes the data folder itself.
  ${If} $UpdateMode <> 1
    ${If} $DeleteAppDataCheckboxState = 1
      nsExec::Exec '"$INSTDIR\pool-core.exe" uninstall-cleanup --delete-data'
    ${Else}
      nsExec::Exec '"$INSTDIR\pool-core.exe" uninstall-cleanup'
    ${EndIf}
    Pop $0
  ${EndIf}
!macroend
