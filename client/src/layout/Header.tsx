import { NavLink, useParams } from "react-router"
import {
  LayoutDashboard,

  User,
  Settings,

  Bell,
  Building2,
} from "lucide-react"
import { Input } from "@/components/ui/input"

export default function Header() {

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

        {/* LEFT: Logo */}
        <div className="flex items-center gap-8">
          <div>
            <h1 className="text-xl font-bold bg-gradient-to-r from-indigo-500 via-purple-500 to-emerald-500 bg-clip-text text-transparent">
              EstateCRM
            </h1>
          </div>

          {/* Navigation */}
          <nav className="hidden xl:flex items-center gap-2">
            {[
              { to: "/dashboard", label: "Панель управления", icon: LayoutDashboard },
              { to: "/company-list", label: "Компании", icon: Building2 },
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

        {/* CENTER: Search */}
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

        {/* RIGHT: Actions */}
        <div className="flex items-center gap-4">

          {/* Notifications */}
          <button className="relative p-2 rounded-xl hover:bg-slate-100 transition">
            <Bell size={18} className="text-slate-600" />
            <span className="absolute -top-1 -right-1 w-2 h-2 bg-emerald-500 rounded-full" />
          </button>

          {/* Profile */}
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

          {/* Settings */}
          <NavLink
            to="/settings"
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