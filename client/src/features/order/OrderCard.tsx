import AddPropertyToOrderDialog from "@/shared/forms/AddPropertyToOrderDialog";
import type { IOrder } from "@/types/order.interface";
import { useDraggable } from '@dnd-kit/react';
import PropertyInCard from "./PropertyInCard";

interface IProps {
    order: IOrder
}

export default function OrderCard({ order }: IProps) {

    const { ref } = useDraggable({
        id: String(order.id)
    })

    const grouped = {
        SELECTION: [],
        SHOW_ONLINE: [],
        SHOW_OFFLINE: [],
        DEAL: []
    } as Record<string, any[]>

    order.properties?.forEach((p: any) => {
        grouped[p.status]?.push(p)
    })

    return (
        <div
            ref={ref}
            className="bg-white rounded-2xl p-4 shadow-sm hover:shadow-md transition space-y-4 border cursor-grab active:cursor-grabbing"
        >

            <div className="flex justify-between items-start">

                <div>
                    <p className="font-semibold text-sm">
                        {order.client.firstName} {order.client.lastName}
                    </p>

                    <p className="text-xs text-muted-foreground">
                        {order.city}
                    </p>
                </div>

                <span className="text-xs px-2 py-1 rounded-full bg-slate-100">
                    {order.dealType}
                </span>

            </div>

            <p className="text-sm text-slate-600 line-clamp-3">
                {order.description}
            </p>
            <div className="space-y-3">

                {grouped.SELECTION.length > 0 && (
                    <div>
                        <p className="text-xs font-semibold text-blue-600 mb-1">
                            Подбор
                        </p>
                        <div className="space-y-2">
                            {grouped.SELECTION.map((p) => (
                                <PropertyInCard key={p.propertyId} property={p} orderId={order.id} />
                            ))}
                        </div>
                    </div>
                )}

                {grouped.SHOW_ONLINE.length > 0 && (
                    <div>
                        <p className="text-xs font-semibold text-indigo-600 mb-1">
                            Онлайн показ
                        </p>
                        <div className="space-y-2">
                            {grouped.SHOW_ONLINE.map((p) => (
                                <PropertyInCard key={p.propertyId} property={p} orderId={order.id} />
                            ))}
                        </div>
                    </div>
                )}

                {grouped.SHOW_OFFLINE.length > 0 && (
                    <div>
                        <p className="text-xs font-semibold text-emerald-600 mb-1">
                            Оффлайн показ
                        </p>
                        <div className="space-y-2">
                            {grouped.SHOW_OFFLINE.map((p) => (
                                <PropertyInCard key={p.propertyId} property={p} orderId={order.id} />
                            ))}
                        </div>
                    </div>
                )}

                {order.properties.length === 0 && (
                    <p className="text-xs text-muted-foreground">
                        Объекты не добавлены
                    </p>
                )}

            </div>

            <div className="pt-2 border-t">
                <AddPropertyToOrderDialog order={order} />
            </div>

        </div>
    )
}