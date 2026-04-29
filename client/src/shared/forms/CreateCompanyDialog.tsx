import { Button } from "@/components/ui/button";
import { Dialog, DialogHeader, DialogTrigger, DialogContent, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { DialogClose } from "@radix-ui/react-dialog";

import { useForm } from "react-hook-form";
import { useCreateCompany } from "../hooks/useCompany";
import type { ICreateCompany } from "@/types/company.interface";



export default function CreateCompanyDialog() {
  const form = useForm<ICreateCompany>({
    mode: "onChange",
  })
  const { mutate: createCompany } = useCreateCompany();
  const onSubmit = (name: string) => {
    console.log(name);
    createCompany({ name });
  }
  return (

    <div>
      <Dialog  >
        <Form {...form}>
          <form className="w-full">
            <DialogTrigger className="px-2 py-1  border-2 rounded-[30px]">+</DialogTrigger>

            <DialogContent className="sm:max-w-[425px]">
              <DialogHeader>
                <DialogTitle>Добавить компанию</DialogTitle>
              </DialogHeader>

              <div className="grid gap-4">
                <div className="grid gap-3">
                  <FormField
                    control={form.control}
                    name="name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Имя компании</FormLabel>
                        <FormControl>
                          <Input placeholder="username123"    {...field} value={field.value || ''} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )} />

                </div>
              </div>
              <DialogFooter>
                <DialogClose asChild>
                  <Button>Отмена</Button>
                </DialogClose>
                <Button type="submit" onClick={form.handleSubmit((data) => onSubmit(data.name))}>Добавить</Button>
              </DialogFooter>
            </DialogContent>
          </form>
        </Form>
      </Dialog>
    </div>
  )
}
