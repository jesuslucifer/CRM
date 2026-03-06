import { Outlet } from "react-router"
import { ToastContainer } from "react-toastify"
import CompanyHeader from "./CompanyHeader"

export default function CompanyLayout() {
    return (
        <div className="min-h-screen bg-slate-50 flex flex-col">
            <CompanyHeader />

            <main className="flex-1 p-8">
                <Outlet />
            </main>

            <ToastContainer />
        </div>
    )
}