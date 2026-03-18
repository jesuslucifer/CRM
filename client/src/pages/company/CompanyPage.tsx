import { useCurrentCompany } from "@/shared/hooks/useCompany"
import { useMemo } from "react"
import { useParams } from "react-router"
import { Building2, MapPin, Phone, Mail, Globe } from "lucide-react"

export default function CompanyPage() {

    const { data: company } = useCurrentCompany()

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

            <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {[
                    { label: "Объектов в продаже", value: "124" },
                    { label: "Активных сделок", value: "38" },
                    { label: "Сотрудников", value: "56" },
                ].map((item) => (
                    <div
                        key={item.label}
                        className="bg-white rounded-2xl p-6 shadow-md border border-slate-100 hover:shadow-lg transition"
                    >
                        <p className="text-sm text-slate-500">{item.label}</p>
                        <p className="text-2xl font-bold text-slate-800 mt-2">
                            {item.value}
                        </p>
                    </div>
                ))}
            </section>

            <section className="grid grid-cols-1 lg:grid-cols-3 gap-8">

                <div className="lg:col-span-2 bg-white rounded-2xl p-6 shadow-md border border-slate-100">
                    <h2 className="text-lg font-semibold text-slate-800 mb-4">
                        О компании
                    </h2>

                    <p className="text-slate-600 leading-relaxed">
                        Компания {company?.name || "Estate Group"} работает на рынке
                        недвижимости более 10 лет. Мы специализируемся на продаже,
                        аренде и инвестиционном сопровождении объектов жилой и
                        коммерческой недвижимости.
                    </p>

                    <p className="text-slate-600 leading-relaxed mt-4">
                        Наша миссия — создавать прозрачные и эффективные решения для
                        клиентов, используя современные технологии управления
                        недвижимостью.
                    </p>
                </div>

                <div className="bg-white rounded-2xl p-6 shadow-md border border-slate-100 space-y-4">
                    <h2 className="text-lg font-semibold text-slate-800">
                        Контакты
                    </h2>

                    <div className="flex items-center gap-3 text-slate-600">
                        <MapPin size={18} />
                        <span>Москва, ул. Примерная, 12</span>
                    </div>

                    <div className="flex items-center gap-3 text-slate-600">
                        <Phone size={18} />
                        <span>+7 (999) 123-45-67</span>
                    </div>

                    <div className="flex items-center gap-3 text-slate-600">
                        <Mail size={18} />
                        <span>info@estatecrm.ru</span>
                    </div>

                    <div className="flex items-center gap-3 text-slate-600">
                        <Globe size={18} />
                        <span>www.estatecrm.ru</span>
                    </div>
                </div>
            </section>

            <section className="bg-gradient-to-r from-emerald-50 to-indigo-50 
        border border-emerald-100
        rounded-2xl p-6 shadow-sm">

                <h3 className="text-md font-semibold text-slate-800 mb-2">
                    Статус компании
                </h3>

                <p className="text-slate-600 text-sm">
                    Компания активно развивается, расширяет портфель объектов
                    и внедряет современные CRM-решения для автоматизации
                    процессов продаж.
                </p>
            </section>

        </div>
    )
}