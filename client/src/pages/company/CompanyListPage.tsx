import { Card, CardContent } from "@/components/ui/card";
import CompanyList from "@/features/company/CompanyList";
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
            <div className="bg-white rounded-3xl shadow-xl p-8 transition hover:shadow-2xl">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-semibold">Мои компании</h2>
                    <CreateCompanyDialog />
                </div>

                <Separator className="mb-6" />
                <CompanyList companies={companies} />

            </div>
        </>
    )
}
