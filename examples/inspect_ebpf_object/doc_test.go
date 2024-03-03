package inspectebpfobject

import (
	"fmt"
	"log"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go dummy dummy.c -- -I../headers

func TestDocLoadCollectionSpec(t *testing.T) {
	// Parse an ELF into a CollectionSpec.
	// bpf_prog.o is the result of compiling BPF C code.
	spec, err := ebpf.LoadCollectionSpec("dummy_bpfel.o")
	if err != nil {
		panic(err)
	}

	// Look up the MapSpec and ProgramSpec in the CollectionSpec.
	m := spec.Maps["my_map"]
	p := spec.Programs["my_prog"]
	// Note: We've omitted nil checks for brevity, take a look at
	// LoadAndAssign for an automated way of checking for maps/programs.

	// Inspect the map and program type.
	t.Logf("map's type: %v, program's type: %v\n", m.Type, p.Type)

	// Print the map's key and value BTF types.
	t.Logf("map's key: %v, map's value: %v\n", m.Key, m.Value)

	// Print the program's instructions in a human-readable form,
	// similar to llvm-objdump -S.
	t.Logf("instructions in program:\n %v\n", p.Instructions)
}

func TestDocNewCollection(t *testing.T) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}
	spec, err := ebpf.LoadCollectionSpec("dummy_bpfel.o")
	if err != nil {
		panic(err)
	}
	t.Logf("%+v", spec)
	for _, v := range spec.Maps {
		t.Logf("\033[31mmap:\033[0m %v %+v\n", v.Name, v.String())
	}
	for _, v := range spec.Programs {
		t.Logf("\033[31mprogram:\033[0m %+v\n", v)
	}
	// Instantiate a Collection from a CollectionSpec.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	// Close the Collection before the enclosing function returns.
	defer coll.Close()

	// Obtain a reference to 'my_map'.
	m := coll.Maps["my_map"]

	cur := 0
	err = m.Lookup(uint32(1), &cur)
	if err == nil {
		t.Error("the key should not exist")
	}

	t.Logf("\033[31m previous:\033[0m %v\n", cur)

	// Set map key '1' to value '2'.
	if err := m.Put(uint32(1), uint64(2)); err != nil {
		panic(err)
	}

	var now uint64
	err = m.Lookup(uint32(1), &now)
	if err != nil {
		panic(err)
	}
	t.Logf("\033[31m now:\033[0m %v\n", now)
	// t.Logf("\033[31mmap:\033[0m %v\n", m)

	t.Logf("%+v", coll)
}

// DocLoadAndAssignObjs {
type myObjs struct {
	MyMap  *ebpf.Map     `ebpf:"my_map"`
	MyProg *ebpf.Program `ebpf:"my_prog"`
}

func (objs *myObjs) Close() error {
	if err := objs.MyMap.Close(); err != nil {
		return err
	}
	if err := objs.MyProg.Close(); err != nil {
		return err
	}
	return nil
}

// }

func TestDocLoadAndAssign(t *testing.T) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}
	spec, err := ebpf.LoadCollectionSpec("dummy_bpfel.o")
	if err != nil {
		panic(err)
	}

	// Insert only the resources specified in 'obj' into the kernel and assign
	// them to their respective fields. If any requested resources are not found
	// in the ELF, this will fail. Any errors encountered while loading Maps or
	// Programs will also be returned here.
	var objs myObjs
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()
	var val uint64
	err = objs.MyMap.Lookup(uint32(1), &val)
	if err == nil {
		t.Error("the key should not exist")
	}
	t.Log(val)
	// Interact with MyMap through the custom struct.
	if err := objs.MyMap.Put(uint32(1), uint64(2)); err != nil {
		panic(err)
	}
	err = objs.MyMap.Lookup(uint32(1), &val)
	if err != nil || val != 2 {
		t.Error("the value is mismatched")
	}
	t.Log(val)
}

func TestDocBTFTypeByName(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("dummy_bpfel.o")
	if err != nil {
		panic(err)
	}

	// Look up the __64 type declared in linux/bpf.h.
	tp, err := spec.Types.AnyTypeByName("__u64")
	if err != nil {
		panic(err)
	}
	fmt.Println(tp)
}
