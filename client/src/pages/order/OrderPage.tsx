import OrderRow from "@/features/order/orderRow"
import OrderTable from "@/features/order/OrderTable"
import CreateOrderDialog from "@/shared/forms/CreateOrderDialog"
import { useCurrentCompany } from "@/shared/hooks/useCompany"
import { useGetOrdersByCompany } from "@/shared/hooks/useOrder"
import { NavLink } from "react-router"

export default function OrderPage() {

  const { data: company } = useCurrentCompany()
  const { data: orders } = useGetOrdersByCompany(company?.id!)

  return (
    <>


      <div className="p-8 space-y-6 bg-slate-50 min-h-screen">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold">Заявки</h1>
          <CreateOrderDialog />
        </div>
        <div className="bg-white rounded-3xl shadow-xl border overflow-hidden">
          <OrderTable orders={orders} />
        </div>
      </div>
    </>

  )
}