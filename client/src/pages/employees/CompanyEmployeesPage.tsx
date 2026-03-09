import { useMemo, useState } from "react"
import { useCreateCompany, useCreateCompanyEmployee, useCurrentCompany, useDeleteCompanyEmployee, useGetCompanyById } from "@/shared/hooks/useCompany"

import {
    Card,
    CardContent,
    CardHeader,
    CardTitle,
} from "@/components/ui/card"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogFooter,
    DialogTrigger,
} from "@/components/ui/dialog"


import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"



import {
    MoreVertical,
    Plus,
    Trash,
    Pencil,
    Search,
} from "lucide-react"
import type { ICreateEmployee, IEmployees } from "@/service/company.service"
import { DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenu } from "@/components/ui/dropdown-menu"
import { Badge } from "@/components/ui/badge"
import { useForm } from "react-hook-form"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { useParams } from "react-router"



export default function CompanyEmployeesPage() {
    const { data: currentCompany } = useCurrentCompany()
    const company_id = currentCompany?.id!
    const form = useForm<ICreateEmployee>({
        mode: "onChange",
    })
    const [search, setSearch] = useState("")
    const [selectedEmployee, setSelectedEmployee] = useState<IEmployees | null>(null)
    const { mutate: deleteEmployee } = useDeleteCompanyEmployee(company_id)

    const [dialogOpen, setDialogOpen] = useState(false)
    const { mutate: createEmployee } = useCreateCompanyEmployee(company_id)
    const employees = currentCompany?.employees
    if (employees?.length === 0) return <div>Нет Сотрудников</div>

    return (
        <div className="p-8 space-y-6">



            <div className="flex items-center justify-between">

                <div>
                    <h1 className="text-2xl font-semibold">Сотрудники</h1>
                    <p className="text-slate-500 text-sm">
                        Управление сотрудниками компании
                    </p>
                </div>

                <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
                    <DialogTrigger asChild>
                        <Button className="flex gap-2">
                            <Plus size={16} />
                            Добавить сотрудника
                        </Button>
                    </DialogTrigger>
                    <Form {...form}>
                        <form>
                            <DialogContent className="sm:max-w-[420px]">

                                <DialogHeader>
                                    <DialogTitle>Добавить сотрудника</DialogTitle>
                                </DialogHeader>

                                <div className="space-y-4 py-4">

                                    <FormField
                                        control={form.control}
                                        name="username"
                                        render={({ field }) => (
                                            <FormItem>
                                                <FormLabel>Имя пользователя</FormLabel>
                                                <FormControl>
                                                    <Input placeholder="username"    {...field} value={field.value || ''} />
                                                </FormControl>
                                                <FormMessage />
                                            </FormItem>
                                        )} />


                                    <FormField
                                        control={form.control}
                                        name="role"
                                        render={({ field }) => (
                                            <FormItem>
                                                <FormLabel>Роль</FormLabel>
                                                <FormControl>
                                                    <Input placeholder="роль"    {...field} value={field.value || ''} />
                                                </FormControl>
                                                <FormMessage />
                                            </FormItem>
                                        )} />

                                </div>

                                <DialogFooter>
                                    <Button variant="outline" onClick={() => setDialogOpen(false)}>
                                        Отмена
                                    </Button>

                                    <Button onClick={form.handleSubmit(data => createEmployee(data))}>Добавить</Button>
                                </DialogFooter>

                            </DialogContent>
                        </form>
                    </Form>
                </Dialog>

            </div>



            <div className="relative max-w-sm">
                <Search
                    size={16}
                    className="absolute left-3 top-3 text-slate-400"
                />
                <Input
                    className="pl-8"
                    placeholder="Поиск сотрудника..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">

                {employees?.map((employee) => {

                    // const user = employee?.user
                    // console.log(employee);

                    return (
                        <Card key={employee?.id} className="hover:shadow-md transition">

                            <CardHeader className="flex flex-row items-center justify-between">

                                <div className="flex items-center gap-3">

                                    <Avatar>
                                        <AvatarImage />
                                        <AvatarFallback>
                                            {employee?.username.slice(0, 2).toUpperCase()}
                                        </AvatarFallback>
                                    </Avatar>

                                    <div>
                                        <CardTitle className="text-base">
                                            {employee?.username}
                                        </CardTitle>

                                        <p className="text-xs text-slate-500">
                                            {employee?.email}
                                        </p>
                                    </div>

                                </div>



                                <DropdownMenu>

                                    <DropdownMenuTrigger asChild>
                                        <Button variant="ghost" size="icon">
                                            <MoreVertical size={16} />
                                        </Button>
                                    </DropdownMenuTrigger>

                                    <DropdownMenuContent align="end">

                                        <DropdownMenuItem
                                            onClick={() => {
                                                setSelectedEmployee(employee)
                                                setDialogOpen(true)
                                            }}
                                        >
                                            <Pencil size={14} className="mr-2" />
                                            Изменить
                                        </DropdownMenuItem>

                                        <DropdownMenuItem onClick={() => deleteEmployee(employee.id)} className="text-red-500">
                                            <Trash size={14} className="mr-2" />
                                            Удалить
                                        </DropdownMenuItem>

                                    </DropdownMenuContent>

                                </DropdownMenu>

                            </CardHeader>

                            <CardContent className="flex items-center justify-between">

                                <Badge variant="secondary">
                                    {employee.role}
                                </Badge>

                                <span className="text-xs text-slate-400">
                                    ID: {employee?.id}
                                </span>

                            </CardContent>

                        </Card>
                    )
                })}
            </div>


        </div>
    )
}