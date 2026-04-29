import ClientsTable from "@/features/clients/ClientsTable";
import CreateClientDialog from "@/shared/forms/CreateClientDialog";

export default function ClientsPage() {

  return (
    <div className="p-8 space-y-6 bg-slate-50 min-h-screen">

      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Клиенты</h1>
        <CreateClientDialog />
      </div>

      <div className="bg-white rounded-3xl shadow-xl border border-slate-200 overflow-hidden">
        <ClientsTable />
      </div>

    </div>
  )
}