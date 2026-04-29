import { Outlet } from "react-router"
import { ToastContainer } from "react-toastify"
import Header from "./Header";

export default function AppLayout() {
    return (
        <div className="min-h-screen bg-slate-50 flex flex-col">
            <Header />

            <main className="flex-1 p-8">
                <Outlet />
            </main>

            <ToastContainer />
        </div>
    )
}