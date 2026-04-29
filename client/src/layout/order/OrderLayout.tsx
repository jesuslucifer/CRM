import { NavLink, Outlet } from "react-router"
import { ToastContainer } from "react-toastify"

export default function OrderLayout() {
    return (
        <div className="min-h-screen bg-slate-50 flex flex-col">

            <header className="bg-white border-b px-8 py-4 flex items-center justify-between">

                <div>
                    <h1 className="text-2xl font-bold">
                        Заявки
                    </h1>
                    <p className="text-sm text-muted-foreground">
                        Управление заявками и сделками
                    </p>
                </div>

                <nav className="flex gap-2 bg-slate-100 p-1 rounded-xl">

                    <NavLink
                        to="list"
                        className={({ isActive }) =>
                            `px-4 py-2 text-sm rounded-lg transition ${isActive
                                ? "bg-white shadow font-medium"
                                : "text-muted-foreground hover:text-black"
                            }`
                        }
                    >
                        Список
                    </NavLink>

                    <NavLink
                        to="kanban"
                        className={({ isActive }) =>
                            `px-4 py-2 text-sm rounded-lg transition ${isActive
                                ? "bg-white shadow font-medium"
                                : "text-muted-foreground hover:text-black"
                            }`
                        }
                    >
                        Канбан
                    </NavLink>

                </nav>

            </header>

            <main className="flex-1 p-8">
                <div className="max-w-full mx-auto">
                    <Outlet />
                </div>
            </main>

            <ToastContainer />
        </div>
    )
}