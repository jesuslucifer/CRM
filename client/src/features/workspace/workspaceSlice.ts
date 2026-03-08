import { createSlice, type PayloadAction } from "@reduxjs/toolkit"

interface WorkspaceState {
  companyId: number | null
  companyName: string | null
  // permissions: string[]
  initialized: boolean
}

const initialState: WorkspaceState = {
  companyId: null,
  companyName: null,
  // permissions: [],
  initialized: false,
}

const workspaceSlice = createSlice({
  name: "workspace",
  initialState,
  reducers: {
    setWorkspace(
      state,
      action: PayloadAction<{
        companyId: number
        companyName: string
        // permissions: string[]
      }>
    ) {
      state.companyId = action.payload.companyId
      state.companyName = action.payload.companyName
      // state.permissions = action.payload.permissions
      state.initialized = true
    },

    clearWorkspace(state) {
      state.companyId = null
      // state.permissions = []
      state.initialized = false
    },
  },
})

export const { setWorkspace, clearWorkspace } = workspaceSlice.actions
export default workspaceSlice.reducer