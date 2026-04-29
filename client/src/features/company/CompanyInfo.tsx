import type { ICompanyById } from "@/types/company.interface"
import { Building2 } from "lucide-react"

export default function CompanyInfo({ company }: { company?: ICompanyById }) {



    return (
        <div className="space-y-8">

            <section className="relative rounded-3xl p-8 overflow-hidden
        bg-gradient-to-r from-indigo-500 via-purple-500 to-emerald-500
        text-white shadow-xl">

                <div className="relative z-10">
                    <div className="flex items-center gap-4">
                        <div className="p-4 bg-white/20 backdrop-blur-md rounded-2xl">
                            <Building2 size={32} />
                        </div>

                        <div>
                            <h1 className="text-3xl font-bold">
                                {company?.name || "Название компании"}
                            </h1>
                            <p className="text-white/80 text-sm mt-1">
                                Лидер в сфере недвижимости и инвестиций
                            </p>
                        </div>
                    </div>
                </div>

                <div className="absolute -right-10 -top-10 w-40 h-40 bg-white/20 rounded-full blur-3xl" />
            </section>

        </div>
    )
}