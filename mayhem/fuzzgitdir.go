package fuzzgitdir

import (
    "strconv"
    fuzz "github.com/AdaLogics/go-fuzz-headers"

    "github.com/belak/go-gitdir/internal/yaml"
    "github.com/belak/go-gitdir/models"
)

func mayhemit(data []byte) int {

    var num int
    if len(data) > 2 {
        num, _ = strconv.Atoi(string(data[0]))
        data = data[1:]
        fuzzConsumer := fuzz.NewConsumer(data)
        
        switch num {

            case 0:
                value, _ := fuzzConsumer.GetString()
                tagString, _ := fuzzConsumer.GetString()

                tag := yaml.ScalarTag(tagString)

                yaml.NewScalarNode(value, tag)
                return 0

            case 1:
                value, _ := fuzzConsumer.GetString()
                tagString, _ := fuzzConsumer.GetString()
                key, _ := fuzzConsumer.GetString()

                tag := yaml.ScalarTag(tagString)
                testNode := yaml.NewScalarNode(value, tag)
                
                testNode.KeyIndex(key)
                return 0

            case 2:
                value, _ := fuzzConsumer.GetString()
                tagString, _ := fuzzConsumer.GetString()
                key, _ := fuzzConsumer.GetString()

                tag := yaml.ScalarTag(tagString)
                testNode := yaml.NewScalarNode(value, tag)
                
                testNode.ValueNode(key)
                return 0

            case 3:
                value, _ := fuzzConsumer.GetString()
                tagString, _ := fuzzConsumer.GetString()
                key, _ := fuzzConsumer.GetString()

                tag := yaml.ScalarTag(tagString)
                testNode := yaml.NewScalarNode(value, tag)
                
                testNode.RemoveKey(key)
                return 0

            case 4:
                value, _ := fuzzConsumer.GetString()
                tagString, _ := fuzzConsumer.GetString()
                key, _ := fuzzConsumer.GetString()

                tag := yaml.ScalarTag(tagString)
                testNode := yaml.NewScalarNode(value, tag)

                var opts yaml.EnsureOptions
                fuzzConsumer.GenerateStruct(&opts)

                Newvalue, _ := fuzzConsumer.GetString()
                NewtagString, _ := fuzzConsumer.GetString()
                Newtag := yaml.ScalarTag(NewtagString)
                newNode := yaml.NewScalarNode(Newvalue, Newtag)

                testNode.EnsureKey(key, newNode, &opts)
                return 0

            case 5:
                value, _ := fuzzConsumer.GetString()
                tagString, _ := fuzzConsumer.GetString()
                tag := yaml.ScalarTag(tagString)
                testNode := yaml.NewScalarNode(value, tag)

                Newvalue, _ := fuzzConsumer.GetString()
                NewtagString, _ := fuzzConsumer.GetString()
                Newtag := yaml.ScalarTag(NewtagString)
                newNode := yaml.NewScalarNode(Newvalue, Newtag)

                testNode.AppendNode(newNode)
                return 0

            case 6:
                value, _ := fuzzConsumer.GetString()
                tagString, _ := fuzzConsumer.GetString()
                tag := yaml.ScalarTag(tagString)
                testNode := yaml.NewScalarNode(value, tag)

                Newvalue, _ := fuzzConsumer.GetString()
                NewtagString, _ := fuzzConsumer.GetString()
                Newtag := yaml.ScalarTag(NewtagString)
                newNode := yaml.NewScalarNode(Newvalue, Newtag)

                testNode.AppendUniqueScalar(newNode)
                return 0

            case 7:
                yaml.EnsureDocument(data)
                return 0

            case 8:
                models.ParseAdminConfig(data)
                return 0

            case 9:
                models.ParseOrgConfig(data)
                return 0

            case 10:
                models.ParseEd25519PrivateKey(data)
                return 0

            case 11:
                models.ParseRSAPrivateKey(data)
                return 0

            case 12:
                models.ParsePublicKey(data)
                return 0

            default:
                models.ParseUserConfig(data)
                return 0
        }
    }
    return 0
}

func Fuzz(data []byte) int {
    _ = mayhemit(data)
    return 0
}