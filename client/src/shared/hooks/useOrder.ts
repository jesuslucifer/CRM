import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import type { OrderFormData } from "../schemas/order.schema"
import { orderService } from "@/service/order.service"
import { toast } from "react-toastify"
import type { IOrderUpdate, IPropertyOrderStatus } from "@/types/order.interface";

export function useCreateOrder(companyId: number) {
    const qc = useQueryClient();
    const { mutate, isPending } = useMutation({
        mutationKey: ['orders', companyId],
        mutationFn: (orderData: OrderFormData) => orderService.createOrder(companyId, { ...orderData, status: "NEW" }),
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

export function useUpdateOrder(companyId: number) {
    const qc = useQueryClient();
    const { mutate, isPending } = useMutation({
        mutationFn: ({ orderId, data }: IOrderUpdate) =>
            orderService.updateOrder(orderId, data),

        onSuccess: (_, variables) => {
            qc.invalidateQueries({
                queryKey: ['orders', companyId]
            })
        },
        onError: (error: any) => {
            toast.error(error?.message || "Ошибка при изменении заявки")
        }
    })
    return { mutate, isPending }
}
export interface IPropertyToOrder {
    orderId: number,
    propertyIds: number[]
}
export function useAddPropertyToOrder(companyId: number) {
    const qc = useQueryClient();
    const { mutate, isPending } = useMutation({
        mutationFn: ({ orderId, propertyIds }: IPropertyToOrder) =>
            orderService.addPropertyToOrder(orderId, propertyIds),

        onSuccess: (_, variables) => {
            qc.invalidateQueries({
                queryKey: ['orders', companyId]
            })
        },
        onError: (error: any) => {
            toast.error(error?.message || "Ошибка при изменении заявки")
        }
    })
    return { mutate, isPending }
}

export function useUpdateOrderPropertyStatus(orderId: number, propertyId: number) {
    const qc = useQueryClient();
    const { mutate, isPending } = useMutation({
        mutationFn: (status: IPropertyOrderStatus) =>
            orderService.updateOrderPropertyStatus(orderId, propertyId, status),

        onSuccess: (_, variables) => {
            qc.invalidateQueries({
                queryKey: ['orders', orderId]
            })
        },
        onError: (error: any) => {
            toast.error(error?.message || "Ошибка при изменении заявки")
        }
    })
    return { mutate, isPending }
}