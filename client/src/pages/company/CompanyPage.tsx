import CompanyInfo from "@/features/company/CompanyInfo"
import CompanyStats from "@/features/company/CompanyStats"
import { useCurrentCompany } from "@/shared/hooks/useCompany"

export default function CompanyPage() {

    const { data: company } = useCurrentCompany()

    return (
        <div className="space-y-8">

            <CompanyInfo company={company} />

            <CompanyStats company={company} />


        </div>
    )
}