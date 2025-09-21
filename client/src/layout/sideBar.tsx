import { Link } from "react-router";

export default function SideBar() {
  return (
    <aside className="w-64 bg-white shadow-lg p-4">
        <nav className="space-y-2">
          <Link to="/profile" className="block hover:underline">
            Профиль
          </Link>
          <Link to="/dashboard" className="block hover:underline">
            Dashboard
          </Link>
          <Link to="/deals" className="block hover:underline">
            Deals List
          </Link>
          <Link to="/deals/kanban" className="block hover:underline">
            Deals Kanban
          </Link>
          <Link to="/leads" className="block hover:underline">
            Leads
          </Link>
          <Link to="/contacts" className="block hover:underline">
            Contacts
          </Link>
          <Link to="/settings" className="block hover:underline">
            Settings
          </Link>
        </nav>
      </aside>
  )
}
