import { NavLink } from "react-router"
import {
  LayoutDashboard,
  Handshake,
  Users,
  User,
  Settings,
  KanbanSquare,
  Contact,
} from "lucide-react"
import { Input } from "@/components/ui/input"

export default function SideBar() {
  return (
    <aside className="w-72 h-screen sticky top-0 
      bg-gradient-to-b from-white via-indigo-50/40 to-emerald-50/40
      backdrop-blur-xl
      border-r border-white/40
      shadow-[0_10px_40px_rgba(0,0,0,0.05)]
      flex flex-col">

      {/* Logo */}
      <div className="flex">
        <div className="p-6 border-b border-slate-200/60">
          <h1 className="text-xl font-bold bg-gradient-to-r from-indigo-500 via-purple-500 to-emerald-500 bg-clip-text text-transparent">
            EstateCRM
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Управление недвижимостью
          </p>
        </div>
        <div>
          <button

            className="absolute top-4 right-4 p-2 rounded-md bg-white/70 shadow-md hover:bg-white/90 transition"
          >
            <LayoutDashboard size={18} />
          </button>
        </div>
      </div>


      {/* Search */}
      <div className="p-4">
        <Input
          placeholder="Поиск..."
          className="
            bg-white/70 
            border-slate-200 
            shadow-sm
            focus:ring-2 
            focus:ring-indigo-400/50
            focus:border-indigo-300
            transition-all
          "
        />
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 space-y-2">
        {[
          { to: "/profile", label: "Профиль", icon: User },
          { to: "/settings", label: "Настройки", icon: Settings },
        ].map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `
              group flex items-center gap-3 px-4 py-3 rounded-2xl text-sm font-medium
              transition-all duration-300
              ${isActive
                ? `
                    bg-gradient-to-r from-indigo-500 to-emerald-400
                    text-white
                    shadow-lg
                    scale-[1.02]
                  `
                : `
                    text-slate-600
                    hover:bg-white/70
                    hover:shadow-md
                    hover:scale-[1.02]
                  `
              }
            `
            }
          >
            <Icon
              size={18}
              className="transition-colors duration-300 group-hover:text-indigo-500"
            />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Bottom info */}
      <div className="p-4 text-xs text-slate-400 border-t border-slate-200/60">
        © 2026 EstateCRM
      </div>
    </aside >
  )
}