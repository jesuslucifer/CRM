import { Outlet } from "react-router"
import { ToastContainer } from "react-toastify"
import CompanyHeader from "./CompanyHeader"
import CompanySidebar from "./CompanySideBar"
import { WorkspaceProvider } from "@/providers/WorkspaceProvider"

export default function CompanyLayout() {
    return (
        <WorkspaceProvider>
            <div className="min-h-screen bg-slate-50 flex">

                <CompanySidebar />

                <div className="flex-1 flex flex-col">

                    <CompanyHeader />

                    <main className="flex-1 p-8">
                        <Outlet />
                    </main>

                </div>

                <ToastContainer />
            </div>
        </WorkspaceProvider>
    )
}