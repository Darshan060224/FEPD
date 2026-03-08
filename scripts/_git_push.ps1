Set-Location c:\Users\darsh\Desktop\FEPD
git add -A
$status = git status --short
if ($status) {
    Write-Output "--- Changes to commit ---"
    Write-Output $status
    git commit -m "Enhanced Artifacts, Timeline, Configuration tabs with MACB, PID, attack story"
    Write-Output "--- Pushing ---"
    git push 2>&1
    Write-Output "--- Done ---"
} else {
    Write-Output "--- No changes to commit, pushing existing commits ---"
    git push 2>&1
    Write-Output "--- Done ---"
}
