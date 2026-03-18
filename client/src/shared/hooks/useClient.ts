import { ClientsService, type IClient } from "@/service/clients.service";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";

export function useCreateClient(companyId: number) {
    const qc = useQueryClient()
    return useMutation({
        mutationFn: (clientData: IClient) => ClientsService.createClient(companyId, clientData),
        mutationKey: ['client', companyId],
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ["clients", companyId] });
            toast.success('Клиент успешно добавлен')
        },
        onError: () => {
            toast.error('Ошибка при добавлении клиента')
        },
    })
}
export function useGetCompanyClient(companyId: number) {
    return useQuery({
        queryKey: ['clients', companyId],
        queryFn: () => ClientsService.getCompanyClient(companyId)
    })
}