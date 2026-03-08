import { NavLink, useParams } from "react-router"
import {
    LayoutDashboard,
    Building2,
    Users,
    Home,
    Power
} from "lucide-react"

export default function CompanySidebar() {
    const { companyId } = useParams<{ companyId: string }>()

    const items = [
        {
            label: "О компании",
            icon: Building2,
            to: `/company/${companyId}/company`
        },
        {
            label: "CRM",
            icon: LayoutDashboard,
            to: `/company/${companyId}/crm`
        },
        {
            label: "Объекты недвижимости",
            icon: Home,
            to: `/company/${companyId}/real-estate`
        },
        {
            label: "Сотрудники",
            icon: Users,
            to: `/company/${companyId}/employees`
        },
        {
            label: "Выйти из компании",
            icon: Power,
            to: `/`,
            danger: true
        },

    ]

    return (
        <aside className="
      w-64
      bg-white
      border-r
      border-slate-200
      flex flex-col
    ">

            {/* Logo */}
            <div className="p-6 border-b">
                <h2 className="font-bold text-lg">
                    EstateCRM
                </h2>
            </div>

            {/* Navigation */}
            <nav className="flex-1 p-3 space-y-1">

                {items.map(({ label, icon: Icon, to, danger }) => (
                    <NavLink
                        key={to}
                        to={to}
                        className={({ isActive }) =>
                            `
      flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition
      ${danger
                                ? "text-red-600 hover:bg-red-100"
                                : isActive
                                    ? "bg-indigo-100 text-indigo-600"
                                    : "text-slate-600 hover:bg-slate-100"
                            }
      `
                        }
                    >
                        <Icon size={18} />
                        {label}
                    </NavLink>

                ))}

            </nav>

            <div className="p-4 text-xs text-slate-400 border-t">
                Workspace
            </div>

        </aside>
    )
}