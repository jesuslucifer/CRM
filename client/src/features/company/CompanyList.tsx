import { Card, CardContent } from "@/components/ui/card";
import type { ICompanyUser } from "@/types/user.interface";
import { NavLink } from "react-router";

export default function CompanyList({ companies }: { companies?: ICompanyUser[] }) {


    return (
        <>
            <div className="grid md:grid-cols-2 gap-6">
                {companies?.map((company) => (
                    <Card
                        key={company.id}
                        className="rounded-2xl border border-slate-200 shadow-sm hover:shadow-lg hover:scale-[1.02] transition"
                    >
                        <CardContent className="p-6 space-y-2">
                            <h3 className="font-semibold text-lg">{company.name}</h3>
                            <p className="text-sm text-slate-500">{company.role}</p>
                            <NavLink to={`/company/${company?.id}/company`} className="text-indigo-600 hover:underline">
                                Перейти в компанию
                            </NavLink>
                        </CardContent>
                    </Card>
                ))}
            </div>

        </>
    )
}
