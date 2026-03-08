import { useAppSelector } from "@/store/hooks"
import { selectWorkspaceId, selectWorkspaceInitialized } from "./workspaceSelectors"

export function useWorkspace() {
  const companyId = useAppSelector(selectWorkspaceId)
  const initialized = useAppSelector(selectWorkspaceInitialized)

  return {
    companyId,
    initialized,
  }
}