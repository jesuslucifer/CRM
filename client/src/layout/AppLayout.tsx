import { Outlet } from "react-router"
import SideBar from "@/layout/SideBar"
import { ToastContainer } from "react-toastify"
import { useState } from "react";
import { LayoutDashboard } from "lucide-react";
import Header from "./Header";

export default function AppLayout() {
    const [show, setShow] = useState<boolean>(false);
    const toggleShow = () => setShow(prev => !prev);
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