import { Card, CardContent } from "@/components/ui/card";
import CreateCompanyDialog from "@/shared/forms/CreateCompanyDialog";
import { useGetAllCompany, useGetCompanyById } from "@/shared/hooks/useCompany";
import { useProfile } from "@/shared/hooks/useProfile";
import { Separator } from "@radix-ui/react-separator";
import { NavLink } from "react-router";

export default function CompanyListPage() {

    const { user } = useProfile();
    const companies = user?.companies
    return (
        <>
            {/* Компании */}
            <div className="bg-white rounded-3xl shadow-xl p-8 transition hover:shadow-2xl">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-semibold">Мои компании</h2>
                    <CreateCompanyDialog />
                </div>

                <Separator className="mb-6" />

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


            </div>
        </>
    )
}
