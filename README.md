# s
userland SIP for protecting dev tools in macos 

TODO: Add readme stuff

# Agents 
All agents should only produce commits and push them to under agent/ prefix branches. 1 commit push per branch. Once created the branch will no longer accept new commits. Ensure you cut the working branch from main tip by fetching and pulling latest main and then rebase your working branch onto it. Squash your work into a single commit before pushing. Linear history is required so if you have stale history your PR will be closed. 

