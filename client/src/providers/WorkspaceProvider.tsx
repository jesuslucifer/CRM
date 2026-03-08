import { useParams } from "react-router"
import { useEffect } from "react"
import { useQuery } from "@tanstack/react-query"

import { setWorkspace } from "@/features/workspace/workspaceSlice"
import { useGetCompanyById } from "@/shared/hooks/useCompany"
import { useAppDispatch } from "@/store/hooks"
import { CompanyService } from "@/service/company.service"
export function WorkspaceProvider({ children }: { children: React.ReactNode }) {

    const { companyId } = useParams()
    const dispatch = useAppDispatch()

    const { data, isLoading } = useQuery({
        queryKey: ["company", companyId],
        queryFn: () => CompanyService.getCompanyById(Number(companyId)),
        enabled: !!companyId,
    })

    useEffect(() => {
        if (data) {
            dispatch(
                setWorkspace({
                    companyId: data.id,
                    companyName: data.name,
                })
            )
        }
    }, [data, dispatch])

    if (isLoading) {
        return <div>Loading workspace...</div>
    }

    return <>{children}</>
}