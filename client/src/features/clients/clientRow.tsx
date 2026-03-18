import type { IClient } from "@/service/clients.service"

interface Props {
    client: IClient
}

const typeMap: Record<string, string> = {
    BUYER: "Покупатель",
    SELLER: "Продавец",
    TENANT: "Арендатор",
    LANDLORD: "Арендодатель"
}

const sourceMap: Record<string, string> = {
    WEBSITE: "Сайт",
    CALL: "Звонок",
    SOCIAL: "Соц. сети",
    REFERRAL: "Рекомендация"
}

export default function ClientRow({ client }: Props) {

    return (
        <tr className="border-t hover:bg-slate-50 transition">

            {/* ФИО */}
            <td className="py-4 px-4 font-medium">
                <div className="flex flex-col">
                    <span>
                        {client.firstName} {client.lastName}
                    </span>

                    {/* источник — как secondary info */}
                    <span className="text-xs text-muted-foreground">
                        {sourceMap[client.clientSource] || client.clientSource}
                    </span>
                </div>
            </td>

            {/* Тип клиента */}
            <td className="py-4 px-4">
                <span className="px-3 py-1 rounded-full text-xs bg-blue-100 text-blue-600">
                    {typeMap[client.clientType] || client.clientType}
                </span>
            </td>

            {/* Email */}
            <td className="py-4 px-4 text-slate-600">
                {client.email || "-"}
            </td>

            {/* Телефон */}
            <td className="py-4 px-4">
                {client.phone || "-"}
            </td>

            {/* Notes */}
            <td className="py-4 px-4 max-w-[250px]">
                <p className="truncate text-slate-500 text-sm">
                    {client.notes || "Нет заметок"}
                </p>
            </td>

            {/* Статус (заглушка под CRM логику) */}
            <td className="py-4 px-4">
                <span className="bg-emerald-100 text-emerald-600 px-3 py-1 rounded-full text-xs">
                    Активный
                </span>
            </td>

        </tr>
    )
}