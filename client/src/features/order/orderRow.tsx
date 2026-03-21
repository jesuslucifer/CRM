interface Props {
    order: any
}

export default function OrderRow({ order }: Props) {
    return (
        <tr className="border-t hover:bg-slate-50 transition">

            <td className="py-3 px-4 font-medium">
                {order.client?.firstName} {order.client?.lastName}
            </td>

            <td className="py-3 px-4">
                {order.city}
            </td>

            <td className="py-3 px-4">
                {order.propertyType}
            </td>

            <td className="py-3 px-4">
                {order.dealType}
            </td>

            <td className="py-3 px-4 max-w-[250px] truncate">
                {order.description}
            </td>

            <td className="py-3 px-4">
                <span className="bg-indigo-100 text-indigo-600 px-3 py-1 rounded-full text-xs">
                    Новая
                </span>
            </td>

        </tr>
    )
}