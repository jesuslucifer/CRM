import type { ICompanyById } from "@/types/company.interface";

export default function CompanyStats({ company }: { company?: ICompanyById }) {


    return (
        <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
                { label: "Объектов в продаже", value: "124" },
                { label: "Активных сделок", value: "38" },
                { label: "Сотрудников", value: `${company?.employees.length || '0'} ` },
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
    )
}