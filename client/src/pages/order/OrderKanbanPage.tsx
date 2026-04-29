import type { IStage } from "@/features/order/OrderStage"
import OrderStage from "@/features/order/OrderStage"
import { useCurrentCompany } from "@/shared/hooks/useCompany";
import { useGetOrdersByCompany, useUpdateOrder } from "@/shared/hooks/useOrder";
import { useProfile } from "@/shared/hooks/useProfile";
import type { IOrder } from "@/types/order.interface";
import { DragDropProvider } from '@dnd-kit/react';
import { useEffect, useState } from "react";

export default function OrderKanbanPage() {

    const stages: IStage[] = [
        { id: 0, name: "Новые", color: "bg-indigo-100 text-indigo-600", status: "NEW" },
        { id: 1, name: "Подбор", color: "bg-blue-100 text-blue-600", status: "SELECTION" },
        { id: 2, name: "Показ", color: "bg-emerald-100 text-emerald-600", status: "SHOW" },
        { id: 3, name: "В сделке", color: "bg-rose-100 text-rose-600", status: "DEAL" },
    ]

    const { data: company } = useCurrentCompany()
    const { data: orders } = useGetOrdersByCompany(company?.id!)
    const { mutate: updateOrder } = useUpdateOrder(company?.id!)

    const [ordersState, setOrdersState] = useState<IOrder[]>([]);
    const me = useProfile()
    useEffect(() => {
        if (!orders) return

        const mapped = orders.map(order => {
            if (order.properties?.length > 0 && order.status === "NEW") {
                return { ...order, status: "SELECTION" }
            }
            return order
        })

        setOrdersState(mapped)

    }, [orders])

    const handleDragEnd = (event: any) => {
        const { operation } = event
        const source = operation.source
        const target = operation.target

        if (!target) return;

        const orderId = Number(source.id);
        const stageId = target.id
        const newStatus = stages.find(s => s.status === stageId)?.status
        const currentOrder = ordersState?.find(order => order.id == orderId)
        if (!currentOrder) return
        if (currentOrder.status === newStatus) return
        // const updatedOrders = ordersState.map(order => {
        //     if (order.id === orderId) {
        //         return {
        //             ...order,
        //             status: newStatus || ''
        //         }
        //     }
        //     return order
        // })
        updateOrder({
            orderId,
            data: {
                id: currentOrder.id,
                clientId: currentOrder.client.id,
                agentId: me.user?.id,
                city: currentOrder.city,
                propertyType: currentOrder.propertyType,
                dealType: currentOrder.dealType,
                description: currentOrder.description,
                status: newStatus || ''
            }
        })
    }

    return (
        <DragDropProvider onDragEnd={handleDragEnd}>
            <div className=" bg-slate-50 min-h-screen space-y-6">

                <div>
                    <h1 className="text-3xl font-bold">
                        Канбан заявок
                    </h1>

                    <p className="text-sm text-muted-foreground">
                        Управление заявками и сделками
                    </p>
                </div>

                <div className="flex justify-between gap-6 overflow-x-auto pb-4">

                    {stages.map((stage) => (
                        <OrderStage
                            key={stage.status}
                            stage={stage}
                            orders={ordersState}
                        />
                    ))}

                </div>

            </div>
        </DragDropProvider>
    )
}