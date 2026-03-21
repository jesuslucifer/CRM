import { NavLink, useParams } from "react-router"
import {
  LayoutDashboard,
  Handshake,
  Users,
  User,
  Settings,
  KanbanSquare,
  Contact,
  Bell,
  Building2,
} from "lucide-react"
import { Input } from "@/components/ui/input"

export default function CompanyHeader() {

  return (
    <header
      className="
        sticky top-0 z-50
        backdrop-blur-xl
        bg-white/70
        border-b border-slate-200
        shadow-sm
      "
    >
      <div className="max-w-[1600px] mx-auto px-8 h-20 flex items-center justify-between">

        <div className="flex items-center gap-8">
          <div>
            <h1 className="text-xl font-bold bg-gradient-to-r from-indigo-500 via-purple-500 to-emerald-500 bg-clip-text text-transparent">
              EstateCRM
            </h1>
          </div>

          <nav className="hidden xl:flex items-center gap-2">
            {[
              // { to: "dashboard", label: "Dashboard", icon: LayoutDashboard },
              // { to: "company", label: "О компании", icon: Building2 },
              // { to: "employees", label: "Сотрудники", icon: Users },
              { to: "crm/deals", label: "Сделка", icon: Handshake },
              { to: "crm/kanban", label: "Kanban", icon: KanbanSquare },
              { to: "crm/leads", label: "Заявки", icon: Users },
              { to: "crm/clients", label: "Клиенты", icon: Contact },
            ].map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `
                  flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium
                  transition-all duration-200
                  ${isActive
                    ? "bg-indigo-100 text-indigo-600"
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                  }
                `
                }
              >
                <Icon size={16} />
                {label}
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="hidden md:block w-96">
          <Input
            placeholder="Поиск объектов, сделок, клиентов..."
            className="
              bg-white
              border-slate-200
              shadow-sm
              focus:ring-2
              focus:ring-indigo-400/40
              focus:border-indigo-300
              transition-all
            "
          />
        </div>

        <div className="flex items-center gap-4">

          <button className="relative p-2 rounded-xl hover:bg-slate-100 transition">
            <Bell size={18} className="text-slate-600" />
            <span className="absolute -top-1 -right-1 w-2 h-2 bg-emerald-500 rounded-full" />
          </button>

          <NavLink
            to="profile"
            className={({ isActive }) =>
              `
              flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium
              transition-all
              ${isActive
                ? "bg-indigo-100 text-indigo-600"
                : "text-slate-600 hover:bg-slate-100"
              }
            `
            }
          >
            <User size={16} />
            Профиль
          </NavLink>

          <NavLink
            to="settings"
            className={({ isActive }) =>
              `
              p-2 rounded-xl transition-all
              ${isActive
                ? "bg-indigo-100 text-indigo-600"
                : "text-slate-600 hover:bg-slate-100"
              }
            `
            }
          >
            <Settings size={18} />
          </NavLink>
        </div>
      </div>
    </header>
  )
}