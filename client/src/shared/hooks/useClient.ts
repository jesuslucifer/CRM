import { ClientsService } from "@/service/clients.service";
import type { IClient } from "@/types/client.interface";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";

export function useCreateClient(companyId: number) {
    const qc = useQueryClient()
    return useMutation({
        mutationFn: (clientData: IClient) => ClientsService.createClient(companyId, clientData),
        mutationKey: ['clients', companyId],
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