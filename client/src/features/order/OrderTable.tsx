import OrderRow from "@/features/order/orderRow"
import type { IOrder } from "@/types/order.interface"

export default function OrderTable({ orders }: { orders?: IOrder[] }) {


    return (

        <table className="w-full text-sm">

            <thead className="bg-slate-100 text-slate-600">
                <tr>
                    <th className="py-4 px-4 text-left">Клиент</th>
                    <th className="py-4 px-4 text-left">Город</th>
                    <th className="py-4 px-4 text-left">Тип</th>
                    <th className="py-4 px-4 text-left">Сделка</th>
                    <th className="py-4 px-4 text-left">Описание</th>
                    <th className="py-4 px-4 text-left">Статус</th>
                </tr>
            </thead>

            <tbody>
                {orders?.map(order => (
                    <OrderRow key={order.id} order={order} />
                ))}
            </tbody>

        </table>


    )
}