// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package report

import (
	"fmt"
	"go/types"
)

func groupDeclarations(pkg *Package) error {
	associations := typeAssociations{
		declarations: pkg.Types,
		byObject:     make(map[*types.TypeName]int),
	}
	byName := make(map[string]int)
	for i, typ := range pkg.Types {
		associations.byObject[typ.Object] = i
		byName[typ.Name] = i
	}

	var functions []Function
	for _, function := range pkg.Functions {
		if function.Receiver != "" {
			index, ok := byName[function.Receiver]
			if !ok {
				return fmt.Errorf("method %q has no public receiver declaration %q", function.Name, function.Receiver)
			}
			pkg.Types[index].Methods = append(pkg.Types[index].Methods, function)
			continue
		}
		signature, ok := function.Object.Type().(*types.Signature)
		if !ok {
			return fmt.Errorf("function %q has no signature", function.Name)
		}
		index, matches := -1, 0
		for i := 0; i < signature.Results().Len(); i++ {
			if match := associations.match(signature.Results().At(i).Type(), true); match >= 0 {
				index = match
				matches++
			}
		}
		if matches == 1 {
			pkg.Types[index].Functions = append(pkg.Types[index].Functions, function)
		} else {
			functions = append(functions, function)
		}
	}
	pkg.Functions = functions

	var constants []Constant
	for _, constant := range pkg.Constants {
		if index := associations.match(constant.Type, false); index >= 0 {
			pkg.Types[index].Constants = append(pkg.Types[index].Constants, constant)
		} else {
			constants = append(constants, constant)
		}
	}
	pkg.Constants = constants

	var variables []Variable
	for _, variable := range pkg.Variables {
		index := associations.match(variable.Objects[0].Type(), false)
		for _, object := range variable.Objects[1:] {
			if associations.match(object.Type(), false) != index {
				index = -1
				break
			}
		}
		if index >= 0 {
			pkg.Types[index].Variables = append(pkg.Types[index].Variables, variable)
		} else {
			variables = append(variables, variable)
		}
	}
	pkg.Variables = variables
	return nil
}

type typeAssociations struct {
	declarations []Type
	byObject     map[*types.TypeName]int
}

func (a typeAssociations) match(t types.Type, containers bool) int {
	for {
		switch typed := t.(type) {
		case *types.Alias:
			if index, ok := a.byObject[typed.Origin().Obj()]; ok {
				return index
			}
			t = types.Unalias(typed)
		case *types.Named:
			if index, ok := a.byObject[typed.Origin().Obj()]; ok {
				return index
			}
			if typed.Obj().Pkg() != nil {
				for i, declaration := range a.declarations {
					if declaration.Object.IsAlias() && types.Identical(types.Unalias(declaration.Object.Type()), typed) {
						return i
					}
				}
			}
			return -1
		case *types.Pointer:
			t = typed.Elem()
		case *types.Slice:
			if !containers {
				return -1
			}
			t = typed.Elem()
		case *types.Array:
			if !containers {
				return -1
			}
			t = typed.Elem()
		default:
			return -1
		}
	}
}
