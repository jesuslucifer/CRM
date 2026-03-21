import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { OrderFormData } from "../schemas/order.schema"
import { orderService } from "@/service/order.service"
import { toast } from "react-toastify"

export function useCreateOrder(companyId: number) {
    const qc = useQueryClient();
    const { mutate, isPending } = useMutation({
        mutationKey: ['orders', companyId],
        mutationFn: (orderData: OrderFormData) => orderService.createOrder(companyId, orderData),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ['orders', companyId] })
            toast(
                "Заявка успешно создана",
            )
        },
        onError: (err: Error) => {
            toast(err.name || "Ошибка при создании заявки",
            )
        }
    })

    return { mutate, isPending }
}
export function useGetOrdersByCompany(companyId: number) {
    return useQuery({
        queryKey: ["orders", companyId],
        queryFn: () => orderService.getOrdersByCompany(companyId),

    })
}