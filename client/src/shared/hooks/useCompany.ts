import { CompanyService, type ICreateCompany  } from "@/service/company.service";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
 

export function useCreateCompany() {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: (payload: ICreateCompany) => CompanyService.createCompany(payload),
         onSuccess: () => qc.invalidateQueries({ queryKey: ["company", "create_company"] }),
})}

export function useGetAllCompany(){
return useQuery({
queryKey:['company','company-list'],
queryFn:() =>  CompanyService.getCompanyList()
})
}
export function useGetCompanyById(id: number){
const {data} =  useQuery({
    queryKey:['company','company-list'],
    queryFn:() =>  CompanyService.getCompanyById(id)
})
return data
}