import type { RootState } from "@/store/store"

 

export const selectWorkspaceId = (state: RootState) =>
  state.workspace.companyId

// export const selectWorkspacePermissions = (state: RootState) =>
//   state.workspace.permissions

export const selectWorkspaceInitialized = (state: RootState) =>
  state.workspace.initialized