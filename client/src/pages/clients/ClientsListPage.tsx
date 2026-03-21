import ClientRow from "@/features/clients/clientRow";
import CreateClientDialog from "@/shared/forms/CreateClientDialog";
import { useGetCompanyClient } from "@/shared/hooks/useClient";
import { useCurrentCompany } from "@/shared/hooks/useCompany";

export default function ContactsListPage() {

  const { data: company } = useCurrentCompany()
  const { data: clients } = useGetCompanyClient(company?.id!)

  return (
    <div className="p-8 space-y-6 bg-slate-50 min-h-screen">

      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Клиенты</h1>
        <CreateClientDialog />
      </div>

      <div className="bg-white rounded-3xl shadow-xl border border-slate-200 overflow-hidden">

        <table className="w-full text-sm">

          <thead className="bg-slate-100 text-slate-600">
            <tr className="text-left">
              <th className="py-4 px-4">ФИО</th>
              <th className="py-4 px-4">Тип</th>
              <th className="py-4 px-4">Email</th>
              <th className="py-4 px-4">Телефон</th>
              <th className="py-4 px-4">Заметки</th>
              <th className="py-4 px-4">Статус</th>
            </tr>
          </thead>

          <tbody>
            {clients?.map(client => (
              <ClientRow
                key={client.id}
                client={client}
              />
            ))}
          </tbody>

        </table>

      </div>

    </div>
  )
}