import OrderRow from "@/features/order/orderRow"
import CreateOrderDialog from "@/shared/forms/CreateOrderDialog"
import { useCurrentCompany } from "@/shared/hooks/useCompany"
import { useGetOrdersByCompany } from "@/shared/hooks/useOrder"

export default function LeadsListPage() {

  const { data: company } = useCurrentCompany()
  const { data: orders } = useGetOrdersByCompany(company?.id!)

  return (
    <div className="p-8 space-y-6 bg-slate-50 min-h-screen">

      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Заявки</h1>
        <CreateOrderDialog />
      </div>

      <div className="bg-white rounded-3xl shadow-xl border overflow-hidden">

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

      </div>

    </div>
  )
}