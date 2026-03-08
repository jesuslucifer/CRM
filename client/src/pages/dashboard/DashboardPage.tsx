import { Card, CardContent } from "@/components/ui/card"
import CreateCompanyDialog from "@/shared/forms/CreateCompanyDialog"
import { useGetAllCompany, useGetCompanyById } from "@/shared/hooks/useCompany"
import { useProfile } from "@/shared/hooks/useProfile"
import { useGetAllUsers } from "@/shared/hooks/useUser"
import { Separator } from "@radix-ui/react-separator"
import { useEffect } from "react"
import { NavLink } from "react-router"

export default function DashboardPage() {
  const { user } = useProfile()
  const users = useGetAllUsers()

  const companies = [
    { id: 1, name: "ООО «Моя Компания»", role: "Администратор" },
    { id: 2, name: "CRM Startup", role: "Сотрудник" },
  ]

  const { data: company } = useGetCompanyById(1)
  // const companieses = useGetAllCompany()
  // useEffect(() => {
  //   console.log(company?.employees[0].role);

  // }, [company])
  return (
    <div className="p-8 space-y-8 bg-slate-50 min-h-screen">

      <div>
        <h1 className="text-3xl font-bold">Панель управления</h1>
        <p className="text-slate-500">
          Добро пожаловать, {user?.username}
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {[
          { title: "Активные сделки", value: 24 },
          { title: "Новые лиды", value: 8 },
          { title: "Закрыто в этом месяце", value: "12" },
          { title: "Общий оборот", value: "15 400 000 ₽" },
        ].map((item) => (
          <div
            key={item.title}
            className="bg-white rounded-3xl shadow-xl p-6 hover:scale-105 transition"
          >
            <p className="text-slate-500 text-sm">{item.title}</p>
            <h2 className="text-2xl font-bold mt-2">{item.value}</h2>
          </div>
        ))}
      </div>

      <div className="bg-white rounded-3xl shadow-xl p-8">
        <h2 className="text-xl font-semibold mb-4">Активность команды</h2>
        <p className="text-slate-500">Графики и аналитика продаж</p>
      </div>
      <div className="bg-white rounded-3xl shadow-xl p-8 transition hover:shadow-2xl">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold">Мои компании</h2>
          {/* <CreateCompanyDialog /> */}
          <NavLink to="/company-list">Посмотреть все</NavLink>
        </div>

        <Separator className="mb-6" />

        <div className="grid md:grid-cols-2 gap-6">
          {companies.map((company) => (
            <Card
              key={company.id}
              className="rounded-2xl border border-slate-200 shadow-sm hover:shadow-lg hover:scale-[1.02] transition"
            >
              <CardContent className="p-6 space-y-2">
                <h3 className="font-semibold text-lg">{company.name}</h3>
                <p className="text-sm text-slate-500">{company.role}</p>
              </CardContent>
            </Card>
          ))}
        </div>
        <div className="grid md:grid-cols-2 gap-6">

          <Card
            key={company?.id}
            className="rounded-2xl border border-slate-200 shadow-sm hover:shadow-lg hover:scale-[1.02] transition"
          >
            <CardContent className="p-6 space-y-2">
              <h3 className="font-semibold text-lg">{company?.name}</h3>
              <p className="text-sm text-slate-500">{company?.employees[0].role}</p>
              <p className="text-sm text-slate-500">{company?.id}</p>
              <NavLink to={`/company/${company?.id}/company`} className="text-indigo-600 hover:underline">
                Перейти в компанию
              </NavLink>
            </CardContent>
          </Card>

        </div>

      </div>
    </div >
  )
}