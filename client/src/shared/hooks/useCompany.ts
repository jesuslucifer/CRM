import { useWorkspace } from "@/features/workspace/workspace.hook";
import { CompanyService } from "@/service/company.service";
import type { ICreateEmployee } from "@/types/company.interface";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";


export function useCreateCompany() {

    const qc = useQueryClient()

    return useMutation({
        mutationFn: CompanyService.createCompany,

        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["company", "list"] })
        }
    })

}
export function useGetAllCompany() {

    return useQuery({
        queryKey: ['company', 'list'],
        queryFn: CompanyService.getCompanyList,
    })

}
export function useGetCompanyById(id: number) {

    return useQuery({
        queryKey: ["company", id],
        queryFn: () => CompanyService.getCompanyById(id),
        enabled: !!id
    })

}
export function useCreateCompanyEmployee(companyId: number) {

    const qc = useQueryClient()

    return useMutation({
        mutationFn: (payload: ICreateEmployee) =>
            CompanyService.createCompanyEmployee(companyId, payload),

        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["company", companyId] });
            toast.success("Сотрудник добавлен в компанию")
        },
        onError: (error: any) => {
            toast.error(error?.message || "Ошибка при добавлении сотрудника в компанию")
        }
    })

}
export function useDeleteCompanyEmployee(
    companyId: number,
) {

    const qc = useQueryClient()

    return useMutation({
        mutationFn: (employeeId: number) =>
            CompanyService.deleteCompanyEmployee(companyId, employeeId),

        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["company", companyId] });
            toast.success("Сотрудник удален из компании")
        },
        onError: (error: any) => {
            toast.error(error?.message || "Ошибка при удалении сотрудника из компании")
        }
    })

}
export function useCurrentCompany() {

    const { companyId } = useWorkspace()

    return useQuery({
        queryKey: ["company", companyId],
        queryFn: () => CompanyService.getCompanyById(companyId!),
        enabled: !!companyId,

    })


}