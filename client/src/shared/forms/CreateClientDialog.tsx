import { useForm } from "react-hook-form"

import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
    DialogFooter
} from "@/components/ui/dialog"

import {
    Form,
    FormField,
    FormItem,
    FormLabel,
    FormControl,
    FormMessage
} from "@/components/ui/form"

import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"
import {
    Select,
    SelectTrigger,
    SelectContent,
    SelectItem,
    SelectValue
} from "@/components/ui/select"
import type { IClient } from "@/service/clients.service"
import { useCreateClient } from "../hooks/useClient"
import { useCurrentCompany } from "../hooks/useCompany"


export default function CreateClientDialog() {

    const form = useForm<IClient>({
        mode: "onChange",
        defaultValues: {
            firstName: "",
            lastName: "",
            phone: 0,
            email: "",
            clientType: "",
            clientSource: "",
            notes: ""
        }
    })
    const { data: company } = useCurrentCompany()
    const { mutate: createClient, isPending } = useCreateClient(company?.id!)

    const onSubmit = (data: IClient) => {
        createClient(data)
    }

    return (
        <Dialog>

            <DialogTrigger asChild>
                <Button>
                    Добавить клиента
                </Button>
            </DialogTrigger>

            <DialogContent className="max-w-2xl">

                <DialogHeader>
                    <DialogTitle>
                        Новый клиент
                    </DialogTitle>
                </DialogHeader>

                <Form {...form}>
                    <form
                        onSubmit={form.handleSubmit(onSubmit)}
                        className="space-y-6"
                    >

                        {/* --- ОСНОВНАЯ ИНФОРМАЦИЯ --- */}
                        <div className="space-y-4">

                            <h3 className="text-sm font-semibold text-muted-foreground">
                                Основная информация
                            </h3>

                            <div className="grid grid-cols-2 gap-4">

                                {/* firstName */}
                                <FormField
                                    control={form.control}
                                    name="firstName"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Имя</FormLabel>
                                            <FormControl>
                                                <Input placeholder="Иван" {...field} />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />

                                {/* lastName */}
                                <FormField
                                    control={form.control}
                                    name="lastName"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Фамилия</FormLabel>
                                            <FormControl>
                                                <Input placeholder="Иванов" {...field} />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />

                            </div>

                        </div>

                        {/* --- КОНТАКТЫ --- */}
                        <div className="space-y-4">

                            <h3 className="text-sm font-semibold text-muted-foreground">
                                Контакты
                            </h3>

                            <div className="grid grid-cols-2 gap-4">

                                {/* phone */}
                                <FormField
                                    control={form.control}
                                    name="phone"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Телефон</FormLabel>
                                            <FormControl>
                                                <Input
                                                    placeholder="+7 999 999 99 99"
                                                    {...field}
                                                    onChange={(e) =>
                                                        field.onChange(Number(e.target.value))
                                                    }
                                                />
                                            </FormControl>
                                        </FormItem>
                                    )}
                                />

                                {/* email */}
                                <FormField
                                    control={form.control}
                                    name="email"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Email</FormLabel>
                                            <FormControl>
                                                <Input
                                                    type="email"
                                                    placeholder="mail@gmail.com"
                                                    {...field}
                                                />
                                            </FormControl>
                                        </FormItem>
                                    )}
                                />

                            </div>

                        </div>

                        {/* --- CRM ДАННЫЕ --- */}
                        <div className="space-y-4">

                            <h3 className="text-sm font-semibold text-muted-foreground">
                                CRM данные
                            </h3>

                            <div className="grid grid-cols-2 gap-4">

                                {/* clientType */}
                                <FormField
                                    control={form.control}
                                    name="clientType"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Тип клиента</FormLabel>

                                            <Select
                                                onValueChange={field.onChange}
                                                defaultValue={field.value}
                                            >
                                                <FormControl>
                                                    <SelectTrigger>
                                                        <SelectValue placeholder="Выберите тип" />
                                                    </SelectTrigger>
                                                </FormControl>

                                                <SelectContent>
                                                    <SelectItem value="BUYER">Покупатель</SelectItem>
                                                    <SelectItem value="SELLER">Продавец</SelectItem>
                                                    <SelectItem value="TENANT">Арендатор</SelectItem>
                                                    <SelectItem value="LANDLORD">Арендодатель</SelectItem>
                                                </SelectContent>

                                            </Select>

                                        </FormItem>
                                    )}
                                />

                                {/* clientSource */}
                                <FormField
                                    control={form.control}
                                    name="clientSource"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Источник</FormLabel>

                                            <Select
                                                onValueChange={field.onChange}
                                                defaultValue={field.value}
                                            >
                                                <FormControl>
                                                    <SelectTrigger>
                                                        <SelectValue placeholder="Источник клиента" />
                                                    </SelectTrigger>
                                                </FormControl>

                                                <SelectContent>
                                                    <SelectItem value="CITE">Сайт</SelectItem>
                                                    <SelectItem value="TELEGRAM">Телеграмм</SelectItem>
                                                    <SelectItem value="BROWSER">Браузер</SelectItem>
                                                    <SelectItem value="VK">VK</SelectItem>
                                                    <SelectItem value="AVITO">AVITO</SelectItem>

                                                </SelectContent>

                                            </Select>

                                        </FormItem>
                                    )}
                                />

                            </div>

                        </div>

                        {/* --- NOTES --- */}
                        <FormField
                            control={form.control}
                            name="notes"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Заметки</FormLabel>
                                    <FormControl>
                                        <Textarea
                                            placeholder="Дополнительная информация о клиенте..."
                                            className="min-h-[100px]"
                                            {...field}
                                        />
                                    </FormControl>
                                </FormItem>
                            )}
                        />

                        {/* FOOTER */}
                        <DialogFooter>

                            <Button
                                type="submit"
                                disabled={isPending}
                            >
                                {isPending ? "Создание..." : "Создать клиента"}
                            </Button>

                        </DialogFooter>

                    </form>
                </Form>

            </DialogContent>

        </Dialog>
    )
}