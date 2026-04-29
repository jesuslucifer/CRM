import type { IOrder } from "@/types/order.interface";
import { useDroppable } from '@dnd-kit/react';
import OrderCard from "./OrderCard";
export interface IStage {
    id: number,
    name: string,
    color: string,
    status: string
}
interface IProps {
    stage: IStage,
    orders: IOrder[] | undefined

}
export default function OrderStage({ stage, orders }: IProps) {

    const { ref } = useDroppable({
        id: stage.status
    })

    const filteredOrders = (orders || []).filter(
        (o: any) => o.status === stage.status
    )

    return (
        <div
            ref={ref}
            className="w-90 bg-slate-100 rounded-3xl p-4 flex-shrink-0 flex flex-col"
        >

            <div className="flex justify-between items-center mb-4">

                <h2 className={`text-sm font-semibold px-3 py-1 rounded-full ${stage.color}`}>
                    {stage.name}
                </h2>

                <span className="text-xs text-muted-foreground">
                    {filteredOrders.length}
                </span>

            </div>

            <div className="space-y-4 overflow-y-auto max-h-[70vh] pr-1">

                {filteredOrders.map((order: any) => (
                    <OrderCard
                        key={order.id}
                        order={order}
                    />
                ))}

            </div>

        </div>
    )
}